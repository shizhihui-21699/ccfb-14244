package dev.reachmap.analysis;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** All tunable knobs of one analysis run. */
public final class AnalysisOptions {
    /** Application classes / jars: analyzed as "our code", and the root of trust for entry points. */
    public final List<Path> appRoots = new ArrayList<>();
    /** Dependency jars: analyzed for call edges, but never treated as entry points by default. */
    public final List<Path> libRoots = new ArrayList<>();
    /** Artifact labels parallel to libRoots, used for vulnerability matching. */
    public final List<String> libArtifacts = new ArrayList<>();
    /** Source roots used only to resolve resource files (application.properties, yaml, xml). */
    public final List<Path> resourceRoots = new ArrayList<>();
    public final List<Path> configFiles = new ArrayList<>();

    /** Packages considered "our code" when only class directories are supplied. */
    public final Set<String> appPackages = new LinkedHashSet<>();
    public final Set<String> entryClasses = new LinkedHashSet<>();
    public final Set<String> entryMethods = new LinkedHashSet<>();

    public Path vulnDb;
    public Path outputDir;
    public String name = "app";

    /** Analyze library method bodies as well (needed for deep paths into vulnerable code). */
    public boolean analyzeLibraries = true;
    /** Index JDK classes from the running JVM (jrt:/) for completeness. */
    public boolean includeJdk = false;
    /** Maximum number of concrete dispatch targets before an edge is downgraded to WIDE. */
    public int maxDispatchTargets = 24;
    /** Hard cap on graph nodes to keep pathological classpaths bounded. */
    public int maxNodes = 400_000;
    public int maxDepth = 60;
    /** Treat scheduled jobs / message listeners as entry points. */
    public boolean scheduledAsEntry = true;
    /** Treat static initializers / @PostConstruct as startup entries. */
    public boolean startupAsEntry = true;
    /** Only report, do not fail on missing classes. */
    public boolean strict = false;
    public boolean verbose = false;
    public boolean keepTemp = false;

    public boolean isAppPackage(String internalName) {
        if (appPackages.isEmpty()) return false;
        String n = internalName.replace('/', '.');
        for (String p : appPackages) {
            if (n.startsWith(p + ".") || n.equals(p)) return true;
        }
        return false;
    }
}
