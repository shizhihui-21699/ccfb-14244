package dev.reachmap;

import dev.reachmap.analysis.*;
import dev.reachmap.entry.ConfigCatalog;
import dev.reachmap.entry.EntryPointFinder;
import dev.reachmap.graph.ReachGraph;
import dev.reachmap.load.ClassPath;
import dev.reachmap.model.ClassInfo;
import dev.reachmap.report.JsonReport;
import dev.reachmap.report.MarkdownReport;
import dev.reachmap.report.ReportContext;
import dev.reachmap.util.Json;
import dev.reachmap.util.Log;
import dev.reachmap.vuln.VulnDb;
import dev.reachmap.vuln.Vulnerability;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/** Command line entry point. */
public final class Main {

    public static final String VERSION = "1.0.0";
    private static final List<String> explainPatterns = new ArrayList<>();

    public static void main(String[] argv) {
        try {
            System.exit(run(argv));
        } catch (Exception e) {
            Log.error("Fatal: %s", e);
            if (System.getenv("REACHMAP_DEBUG") != null) e.printStackTrace();
            System.exit(2);
        }
    }

    public static int run(String[] argv) throws IOException {
        AnalysisOptions opts = new AnalysisOptions();
        Path projectFile = null;

        for (int i = 0; i < argv.length; i++) {
            String a = argv[i];
            switch (a) {
                case "--project" -> projectFile = Path.of(require(argv, ++i, a));
                case "--vulndb" -> opts.vulnDb = Path.of(require(argv, ++i, a));
                case "--out" -> opts.outputDir = Path.of(require(argv, ++i, a));
                case "--name" -> opts.name = require(argv, ++i, a);
                case "--app" -> opts.appRoots.add(Path.of(require(argv, ++i, a)));
                case "--lib" -> opts.libRoots.add(Path.of(require(argv, ++i, a)));
                case "--resources" -> opts.resourceRoots.add(Path.of(require(argv, ++i, a)));
                case "--package" -> opts.appPackages.add(require(argv, ++i, a));
                case "--entry-class" -> opts.entryClasses.add(require(argv, ++i, a));
                case "--entry-method" -> opts.entryMethods.add(require(argv, ++i, a));
                case "--jdk" -> opts.includeJdk = true;
                case "--no-libraries" -> opts.analyzeLibraries = false;
                case "--max-depth" -> opts.maxDepth = Integer.parseInt(require(argv, ++i, a));
                case "--max-targets" -> opts.maxDispatchTargets = Integer.parseInt(require(argv, ++i, a));
                case "--strict" -> opts.strict = true;
                case "--explain" -> explainPatterns.add(require(argv, ++i, a));
                case "--verbose", "-v" -> opts.verbose = true;
                case "--quiet" -> { }
                case "--version" -> { System.out.println(VERSION); return 0; }
                case "--help", "-h" -> { usage(); return 0; }
                default -> {
                    if (a.startsWith("--")) { Log.error("Unknown option: %s", a); usage(); return 2; }
                    // Bare argument: a classpath root, split on ':' like java -cp.
                    for (String part : a.split(":")) if (!part.isBlank()) opts.appRoots.add(Path.of(part));
                }
            }
        }
        if (opts.verbose) Log.setLevel(Log.Level.DEBUG);

        if (projectFile != null) applyProjectFile(opts, projectFile);
        if (opts.appRoots.isEmpty()) {
            Log.error("No application class dir/jar given. Use --app <dir|jar> or --project <file>.");
            usage();
            return 2;
        }
        for (Path p : opts.appRoots) {
            if (!Files.exists(p)) { Log.error("Application root does not exist: %s", p); return 2; }
        }

        long t0 = System.nanoTime();
        String projectName = opts.name != null ? opts.name : inferName(opts);
        if (opts.outputDir == null) opts.outputDir = Path.of("reachmap-out", projectName);
        Files.createDirectories(opts.outputDir);

        // ---- index classpath
        ClassPath cp = new ClassPath();
        for (Path p : opts.appRoots) cp.addRoot(p, ClassInfo.Source.APP, artifactOf(p));
        for (Path p : opts.libRoots) cp.addRoot(p, ClassInfo.Source.LIB, artifactOf(p));
        if (opts.includeJdk) addJdk(cp);
        cp.index();

        Map<String, String> artifactVersions = scanArtifactVersions(cp);

        // ---- config resources
        ConfigCatalog config = new ConfigCatalog();
        List<Path> resRoots = new ArrayList<>(opts.resourceRoots);
        if (resRoots.isEmpty()) for (Path p : opts.appRoots) if (Files.isDirectory(p)) resRoots.add(p);
        config.scanRoots(resRoots);
        for (Path p : opts.configFiles) if (Files.isRegularFile(p)) config.scanFile(p);
        Log.info("Config scan: %d file(s), %d class-name candidate(s)", config.filesRead().size(), config.entries().size());

        // ---- DI + entries
        TypeHierarchy th = new TypeHierarchy(cp);
        InjectionModel di = new DiExtractor(cp).build();
        EntryPointFinder finder = new EntryPointFinder(cp, opts,
                new EntryPointFinder.InjectionModelRef(di));
        finder.discover();
        for (String d : finder.diagnostics()) Log.warn("Entry discovery: %s", d);

        // ---- graph
        GraphBuilder builder = new GraphBuilder(cp, th, opts, di, config);
        builder.build(finder.entries());
        ReachGraph graph = builder.graph();

        // ---- vulnerabilities
        if (!explainPatterns.isEmpty()) explain(graph, finder.entries(), explainPatterns);
        VulnDb db = VulnDb.load(opts.vulnDb);
        List<Vulnerability> vulns = db.all();
        if (vulns.isEmpty() && opts.vulnDb != null) Log.warn("Vulnerability DB %s is empty", opts.vulnDb);
        Log.info("Judging %d vulnerability record(s) against the graph", vulns.size());

        ReachabilityAnalyzer analyzer = new ReachabilityAnalyzer(cp, graph, finder.entries(),
                builder.uncertainties(), opts);
        artifactVersions.forEach(analyzer::registerArtifactVersion);
        List<Finding> findings = analyzer.analyze(vulns);

        // ---- reports
        double secs = (System.nanoTime() - t0) / 1e9;
        ReportContext ctx = new ReportContext(projectName, Instant.now().toString(), cp, finder.entries(),
                findings, builder.uncertainties(), graph.nodes().size(), graph.edgeCount(),
                graph.truncatedNodes(), secs, VERSION);

        Path jsonPath = opts.outputDir.resolve("reachability.json");
        Path mdPath = opts.outputDir.resolve("reachability.md");
        Files.writeString(jsonPath, Json.pretty(new JsonReport(ctx).build()), StandardCharsets.UTF_8);
        Files.writeString(mdPath, new MarkdownReport(ctx).render(), StandardCharsets.UTF_8);

        printConsoleSummary(projectName, findings, finder.entries(), cp, graph, secs, jsonPath, mdPath);

        if (opts.strict && !cp.missingClasses().isEmpty()) {
            Log.warn("--strict: %d class(es) missing from the classpath", cp.missingClasses().size());
            return 1;
        }
        return 0;
    }

    private static void printConsoleSummary(String project, List<Finding> findings,
                                            List<dev.reachmap.model.EntryPoint> entries, ClassPath cp,
                                            ReachGraph graph, double secs, Path json, Path md) {
        Map<Verdict, Integer> counts = new EnumMap<>(Verdict.class);
        for (Finding f : findings) counts.merge(f.verdict(), 1, Integer::sum);
        System.out.println();
        System.out.println("ReachMap " + VERSION + " — " + project);
        System.out.printf("  entries=%d  classes=%d  methods=%d  edges=%d  time=%.2fs%n",
                entries.size(), cp.allClasses().size(), graph.nodes().size(), graph.edgeCount(), secs);
        for (Verdict v : Verdict.values()) {
            System.out.printf("  %-12s %d%n", v.name(), counts.getOrDefault(v, 0));
        }
        for (Finding f : findings) {
            if (!f.verdict().needsAction()) continue;
            System.out.printf("  [%s] %s %s  entry=%s%n", f.verdict(), f.vulnerabilityId(),
                    f.confidence().label(),
                    f.entry() == null ? "-" : f.entry().label());
        }
        System.out.println("  report: " + md);
        System.out.println("  json:   " + json);
    }

    /**
     * Debug aid: for each pattern, list matching graph nodes and, where reachable, the proof path.
     * This is how one answers "why did the analyzer not see this hop?" without re-running in a
     * debugger.
     */
    private static void explain(ReachGraph graph, List<dev.reachmap.model.EntryPoint> entries, List<String> patterns) {
        List<dev.reachmap.model.MethodId> roots = new ArrayList<>();
        for (var e : entries) roots.add(e.method());
        ReachGraph.SearchResult r = graph.reachFrom(roots, 60, 400_000);
        for (String pattern : patterns) {
            System.out.println("== explain: " + pattern);
            int shown = 0;
            for (var n : graph.nodes()) {
                String d = n.display();
                if (!d.contains(pattern)) continue;
                List<dev.reachmap.model.Edge> path = r.pathTo(n);
                System.out.println("  " + d + "  -> " + (path == null ? "NOT REACHED" : "reached in "
                        + path.size() + " hop(s)") + "  edgesOut=" + graph.edgesFrom(n).size());
                if (path != null) {
                    for (var e : path) {
                        System.out.println("       " + e.kind().label() + " " + e.from().shortDisplay()
                                + " -> " + e.to().shortDisplay() + (e.line() > 0 ? ":" + e.line() : ""));
                    }
                }
                if (++shown >= 12) { System.out.println("  ..."); break; }
            }
            if (shown == 0) System.out.println("  (no matching node in graph)");
        }
        System.out.println();
    }

    // ------------------------------------------------------------------ helpers

    private static void applyProjectFile(AnalysisOptions opts, Path p) throws IOException {
        Map<String, Object> m = Json.obj(Json.parseFile(p));
        if (m.containsKey("name")) opts.name = Json.str(m, "name", opts.name);
        if (m.containsKey("vulndb") && opts.vulnDb == null) opts.vulnDb = Path.of(Json.str(m, "vulndb", ""));
        for (String s : Json.strList(m, "app")) opts.appRoots.add(resolve(p, s));
        for (String s : Json.strList(m, "lib")) opts.libRoots.add(resolve(p, s));
        for (String s : Json.strList(m, "resources")) opts.resourceRoots.add(resolve(p, s));
        for (String s : Json.strList(m, "configFiles")) opts.configFiles.add(resolve(p, s));
        for (String s : Json.strList(m, "packages")) opts.appPackages.add(s);
        for (String s : Json.strList(m, "entryClasses")) opts.entryClasses.add(s);
        for (String s : Json.strList(m, "entryMethods")) opts.entryMethods.add(s);
        if (m.containsKey("analyzeLibraries")) opts.analyzeLibraries = Json.bool(m, "analyzeLibraries", true);
        if (m.containsKey("maxDepth")) opts.maxDepth = (int) Json.num(m, "maxDepth", opts.maxDepth);
        if (m.containsKey("maxDispatchTargets")) opts.maxDispatchTargets = (int) Json.num(m, "maxDispatchTargets", opts.maxDispatchTargets);
        if (m.containsKey("includeJdk")) opts.includeJdk = Json.bool(m, "includeJdk", false);
        if (m.containsKey("scheduledAsEntry")) opts.scheduledAsEntry = Json.bool(m, "scheduledAsEntry", true);
        if (m.containsKey("startupAsEntry")) opts.startupAsEntry = Json.bool(m, "startupAsEntry", true);
        // Optional explicit classpath from a Maven/Gradle export.
        if (m.containsKey("classpath")) {
            for (String s : Json.strList(m, "classpath")) {
                Path q = resolve(p, s);
                if (Files.isRegularFile(q)) opts.libRoots.add(q);
            }
        }
    }

    private static Path resolve(Path base, String s) {
        Path q = Path.of(s);
        return q.isAbsolute() ? q : base.toAbsolutePath().getParent().resolve(q).normalize();
    }

    private static String require(String[] argv, int i, String opt) {
        if (i >= argv.length) throw new IllegalArgumentException("Missing value for " + opt);
        return argv[i];
    }

    private static String inferName(AnalysisOptions opts) {
        if (!opts.appRoots.isEmpty()) return artifactOf(opts.appRoots.get(0));
        return "app";
    }

    /** Best-effort artifact label from a jar name, class dir, or manifest. */
    static String artifactOf(Path p) {
        String fileName = p.getFileName() == null ? "" : p.getFileName().toString();
        if (Files.isRegularFile(p) && fileName.endsWith(".jar")) {
            try (JarFile jar = new JarFile(p.toFile())) {
                Manifest mf = jar.getManifest();
                if (mf != null) {
                    String bundle = mf.getMainAttributes().getValue("Bundle-SymbolicName");
                    if (bundle != null && !bundle.isBlank()) return bundle.split(";")[0].trim();
                    String title = mf.getMainAttributes().getValue("Implementation-Title");
                    if (title != null && !title.isBlank()) return title.trim();
                }
                // Prefer Maven coordinates embedded in the jar.
                var entries = jar.entries();
                while (entries.hasMoreElements()) {
                    String n = entries.nextElement().getName();
                    if (n.startsWith("META-INF/maven/") && n.endsWith("/pom.properties")) return null; // parsed below
                }
            } catch (IOException ignored) { }
            return stripVersion(fileName.substring(0, fileName.length() - 4));
        }
        if (Files.isDirectory(p)) {
            // Maven: target/classes -> parent should be the module name
            Path parent = p.getParent();
            if (parent != null && p.getFileName().toString().equals("classes")) {
                return parent.getParent() != null ? parent.getParent().getFileName().toString() : "app";
            }
            return fileName.isEmpty() ? "app" : fileName;
        }
        return stripVersion(fileName);
    }

    static String stripVersion(String name) {
        return name.replaceAll("-\\d+(\\.\\d+)+.*$", "").replaceAll("-(SNAPSHOT|RELEASE|Final)$", "");
    }

    /** Collects version strings for artifacts, from pom.properties where available then jar names. */
    static Map<String, String> scanArtifactVersions(ClassPath cp) {
        Map<String, String> out = new LinkedHashMap<>();
        for (ClassPath.Root r : cp.roots()) {
            Path p = r.path();
            String name = p.getFileName() == null ? "" : p.getFileName().toString();
            if (name.endsWith(".jar")) {
                try (JarFile jar = new JarFile(p.toFile())) {
                    var entries = jar.entries();
                    while (entries.hasMoreElements()) {
                        var e = entries.nextElement();
                        String n = e.getName();
                        if (!n.startsWith("META-INF/maven/") || !n.endsWith("/pom.properties")) continue;
                        Properties props = new Properties();
                        try (var in = jar.getInputStream(e)) { props.load(in); }
                        String aid = props.getProperty("artifactId");
                        String ver = props.getProperty("version");
                        if (aid != null && ver != null) {
                            out.put(aid, ver);
                            out.put(r.artifact(), ver);
                        }
                        break;
                    }
                } catch (IOException ignored) { }
                String v = versionFromJarName(name);
                if (v != null) out.putIfAbsent(r.artifact(), v);
            }
        }
        return out;
    }

    static String versionFromJarName(String name) {
        String base = name.endsWith(".jar") ? name.substring(0, name.length() - 4)
                : name.endsWith(".zip") ? name.substring(0, name.length() - 4) : name;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("-([0-9]+(?:\\.[0-9]+)+(?:[-.][A-Za-z0-9]+)*)$").matcher(base);
        return m.find() ? m.group(1) : null;
    }

    /** Indexes the running JDK's classes through the jrt filesystem. */
    private static void addJdk(ClassPath cp) {
        Path jrt = Path.of(System.getProperty("java.home")).resolve("lib").resolve("jrt-fs.jar");
        // The jrt:/ filesystem is exposed via FileSystems; wrapping it as a ClassPath root is not
        // supported by the directory walker, so JDK support is opt-in via an extracted rt image.
        cp.markMissing("java.lang.Object");
        Log.warn("JDK indexing is not enabled in this build (jrt harness absent: %s)", jrt);
    }

    private static void usage() {
        System.out.print("""
            ReachMap — Java vulnerability reachability analysis

            Usage:
              reachmap --app <dir|jar> [--lib <jar>]... [--vulndb db.json] [--out dir]

            Options:
              --project <file.json>   Project description file
              --vulndb <file.json>    Vulnerability database
              --out <dir>             Output directory (default reachmap-out/<name>)
              --name <name>           Project name for reports
              --app <dir|jar>         Application classes (repeatable)
              --lib <jar>             Dependency jar (repeatable)
              --resources <dir>       Extra resource roots to scan for config-driven classes
              --package <prefix>      Treat this package as application code
              --entry-class <fqcn>    Force a class as an entry point
              --entry-method <spec>   Force a method entry: com.acme.Foo#bar or Foo#bar(java.lang.String)
              --no-libraries          Do not descend into library method bodies (faster, less precise)
              --max-depth <n>         Max path depth (default 60)
              --max-targets <n>       Dispatch width before an edge becomes WIDE (default 24)
              --jdk                   Index JDK classes (requires extracted JDK image)
              --strict                Exit non-zero if classes are missing
              -v, --verbose           Debug logging
              --version               Print version
            """);
    }
}
