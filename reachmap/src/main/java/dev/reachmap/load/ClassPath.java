package dev.reachmap.load;

import dev.reachmap.model.ClassInfo;
import dev.reachmap.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;

/**
 * Classpath index.
 *
 * <p>Every class present on the analyzed classpath is indexed by header only; method bodies are
 * read lazily and cached, so scanning hundreds of dependency jars stays cheap. Classes that are
 * missing from the index are recorded explicitly: an unresolvable owner is a real analysis
 * limitation and must surface in the report rather than silently disappear.
 */
public final class ClassPath {

    /** One entry on the analysis classpath. */
    public record Root(Path path, ClassInfo.Source source, String artifact) {}

    private final List<Root> roots = new ArrayList<>();
    private final Map<String, ClassInfo> classes = new HashMap<>();
    private final Map<String, Root> classRoots = new HashMap<>();
    private final Set<String> duplicateClasses = new HashSet<>();
    private final Set<String> missingClasses = ConcurrentHashMap.newKeySet();
    private final List<String> warnings = new ArrayList<>();

    /** Cache of jar entries already read, keyed by jar path then internal class name. */
    private final Map<String, Map<String, byte[]>> jarCache = new ConcurrentHashMap<>();
    private final Map<String, byte[]> classBytesCache = new ConcurrentHashMap<>();

    public void addRoot(Path path, ClassInfo.Source source, String artifact) {
        roots.add(new Root(path, source, artifact));
    }

    // ------------------------------------------------------------------ indexing

    public void index() throws IOException {
        long t0 = System.nanoTime();
        for (Root root : roots) {
            if (Files.isDirectory(root.path())) indexDirectory(root);
            else if (root.path().toString().endsWith(".jar") || root.path().toString().endsWith(".zip")) indexJar(root);
            else if (Files.isRegularFile(root.path())) {
                // .class file passed directly
                byte[] bytes = Files.readAllBytes(root.path());
                ClassInfo ci = BytecodeReader.readHeader(bytes, root.source(), root.artifact(), root.path().toString(), null);
                register(ci, root);
            }
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;
        Log.info("Indexed %d classes from %d root(s) in %d ms (%d app, %d lib)",
                classes.size(), roots.size(), ms, countApp(), classes.size() - countApp());
    }

    private long countApp() {
        return classes.values().stream().filter(ClassInfo::isApp).count();
    }

    private void indexDirectory(Root root) throws IOException {
        try (Stream<Path> s = Files.walk(root.path())) {
            s.filter(p -> p.toString().endsWith(".class") && !isMultiRelease(p, root.path()))
             .forEach(p -> {
                 try {
                     byte[] bytes = Files.readAllBytes(p);
                     ClassInfo ci = BytecodeReader.readHeader(bytes, root.source(), root.artifact(), root.path().toString(), null);
                     register(ci, root);
                     classBytesCache.putIfAbsent(ci.name(), bytes);
                 } catch (Exception e) {
                     warnings.add("Unreadable class " + p + ": " + e.getMessage());
                 }
             });
        }
    }

    private boolean isMultiRelease(Path p, Path base) {
        return base.relativize(p).getName(0).toString().equals("META-INF");
    }

    private void indexJar(Root root) throws IOException {
        Map<String, byte[]> cache = jarCache.computeIfAbsent(root.path().toString(), k -> new HashMap<>());
        try (JarFile jar = new JarFile(root.path().toFile(), false)) {
            Enumeration<JarEntry> en = jar.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (e.isDirectory() || !e.getName().endsWith(".class")) continue;
                if (e.getName().startsWith("META-INF/")) continue;
                try (InputStream in = jar.getInputStream(e)) {
                    byte[] bytes = in.readAllBytes();
                    ClassInfo ci = BytecodeReader.readHeader(bytes, root.source(), root.artifact(),
                            root.path().toString(), null);
                    register(ci, root);
                    cache.put(ci.name(), bytes);
                } catch (Exception ex) {
                    warnings.add("Unreadable class " + e.getName() + " in " + root.path() + ": " + ex.getMessage());
                }
            }
        }
    }

    private void register(ClassInfo ci, Root root) {
        if (ci.name() == null) return;
        ClassInfo prev = classes.putIfAbsent(ci.name(), ci);
        if (prev == null) {
            classRoots.put(ci.name(), root);
        } else {
            // Prefer APP over LIB when the same class shows up twice (target/classes shadows jars).
            if (prev.source() == ClassInfo.Source.LIB && ci.source() == ClassInfo.Source.APP) {
                classes.put(ci.name(), ci);
                classRoots.put(ci.name(), root);
            }
            duplicateClasses.add(ci.name());
        }
    }

    // ------------------------------------------------------------------ lookup

    public ClassInfo get(String internalName) {
        return internalName == null ? null : classes.get(internalName);
    }

    public ClassInfo requireOrNull(String internalName) {
        ClassInfo ci = get(internalName);
        if (ci == null && internalName != null) missingClasses.add(internalName);
        return ci;
    }

    public boolean contains(String internalName) { return classes.containsKey(internalName); }

    public Collection<ClassInfo> allClasses() { return classes.values(); }

    public Set<String> missingClasses() { return missingClasses; }

    public Set<String> duplicateClasses() { return duplicateClasses; }

    public List<String> warnings() { return warnings; }

    public List<Root> roots() { return roots; }

    /** Resolves the bytecode bytes for one class, or null if the class was not indexed. */
    public byte[] bytesOf(String internalName) {
        byte[] cached = classBytesCache.get(internalName);
        if (cached != null) return cached;
        Root root = classRoots.get(internalName);
        if (root == null) return null;
        try {
            byte[] bytes;
            if (Files.isDirectory(root.path())) {
                bytes = Files.readAllBytes(root.path().resolve(internalName + ".class"));
            } else {
                Map<String, byte[]> cache = jarCache.computeIfAbsent(root.path().toString(), k -> new HashMap<>());
                bytes = cache.get(internalName);
                if (bytes == null) {
                    try (JarFile jar = new JarFile(root.path().toFile(), false)) {
                        JarEntry e = jar.getJarEntry(internalName + ".class");
                        if (e == null) return null;
                        try (InputStream in = jar.getInputStream(e)) { bytes = in.readAllBytes(); }
                        cache.put(internalName, bytes);
                    }
                }
            }
            classBytesCache.put(internalName, bytes);
            return bytes;
        } catch (IOException e) {
            warnings.add("Could not read bytes for " + internalName + ": " + e.getMessage());
            return null;
        }
    }

    /** True if the class belongs to the analyzed application (not a dependency jar). */
    public boolean isApp(String internalName) {
        ClassInfo ci = classes.get(internalName);
        return ci != null && ci.isApp();
    }

    /** Class names (internal form) that directly implement or extend the given type. */
    public List<String> directSubtypes(String internalName) {
        List<String> out = new ArrayList<>();
        for (ClassInfo ci : classes.values()) {
            if (internalName.equals(ci.superName())) { out.add(ci.name()); continue; }
            for (String itf : ci.interfaces()) if (internalName.equals(itf)) { out.add(ci.name()); break; }
        }
        return out;
    }

    /** All classes whose name starts with the given package prefix. */
    public List<ClassInfo> classesInPackage(String packagePrefix) {
        String p = packagePrefix.replace('.', '/');
        List<ClassInfo> out = new ArrayList<>();
        for (ClassInfo ci : classes.values()) if (ci.name().startsWith(p)) out.add(ci);
        return out;
    }

    public void markMissing(String internalName) {
        if (internalName != null) missingClasses.add(internalName);
    }
}
