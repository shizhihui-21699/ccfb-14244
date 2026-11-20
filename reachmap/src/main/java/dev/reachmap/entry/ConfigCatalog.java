package dev.reachmap.entry;

import dev.reachmap.util.Json;
import dev.reachmap.util.Log;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Reads configuration resources shipped with the application and extracts class names that the
 * framework will instantiate or dispatch to.
 *
 * <p>Configuration-driven calls are the sneakiest of the hidden call relations: a class name in
 * {@code application.properties} or {@code log4j2.xml} causes code to run on a path that no
 * bytecode edge reveals. We deliberately search broad (any fully-qualified-looking token in any
 * resource file) and then verify the found candidates against the class index, so a hit is a real
 * class rather than a plausible-looking string.
 */
public final class ConfigCatalog {

    private static final Pattern FQCN = Pattern.compile(
            "\\b([a-zA-Z_$][\\w$]*(?:\\.[a-zA-Z_$][\\w$]*){2,})\\b");

    /** One class name discovered in configuration, with provenance. */
    public record ConfiguredClass(String className, String file, int line, String key) {}

    private final List<ConfiguredClass> entries = new ArrayList<>();
    private final List<String> filesRead = new ArrayList<>();

    public List<ConfiguredClass> entries() { return entries; }
    public List<String> filesRead() { return filesRead; }

    public void scanRoots(List<Path> roots) {
        for (Path root : roots) {
            if (Files.isRegularFile(root)) { scanFile(root); continue; }
            if (!Files.isDirectory(root)) continue;
            try (Stream<Path> s = Files.walk(root, 8)) {
                s.filter(Files::isRegularFile).filter(ConfigCatalog::looksLikeConfig).forEach(this::scanFile);
            } catch (IOException e) {
                Log.debug("Config scan failed for %s: %s", root, e.getMessage());
            }
        }
    }

    static boolean looksLikeConfig(Path p) {
        String n = p.getFileName().toString().toLowerCase(Locale.ROOT);
        return n.endsWith(".properties") || n.endsWith(".yaml") || n.endsWith(".yml")
                || n.endsWith(".xml") || n.equals("services") || n.endsWith(".json")
                || n.endsWith(".conf") || n.endsWith(".cfg");
    }

    public void scanFile(Path p) {
        try {
            List<String> lines = Files.readAllLines(p, StandardCharsets.UTF_8);
            filesRead.add(p.toString());
            int no = 0;
            String key = null;
            for (String line : lines) {
                no++;
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("<!--")) continue;
                Matcher km = Pattern.compile("^(?:<([\\w.:-]+)>|([\\w.\\-]+)\\s*[:=]|([\\w.\\-]+)\\s*=)").matcher(trimmed);
                if (km.find()) key = km.group(1) != null ? km.group(1) : km.group(2) != null ? km.group(2) : km.group(3);

                Matcher m = FQCN.matcher(trimmed);
                while (m.find()) {
                    String candidate = m.group(1);
                    String internal = candidate.replace('.', '/');
                    // Heuristic pre-filter: must look like a class path, not a URL/version.
                    if (!isPlausibleClass(internal)) continue;
                    entries.add(new ConfiguredClass(internal, p.toString(), no, key));
                }
            }
        } catch (IOException e) {
            Log.debug("Could not read config %s: %s", p, e.getMessage());
        }
    }

    private static boolean isPlausibleClass(String internal) {
        if (internal.contains("//")) return false;
        String last = internal.substring(internal.lastIndexOf('/') + 1);
        if (last.isEmpty()) return false;
        // Class names conventionally start uppercase; parameters/versions rarely do.
        return Character.isUpperCase(last.charAt(0));
    }

    /** Writes the catalog as JSON for diagnostics. */
    public Map<String, Object> toJson() {
        List<Object> list = new ArrayList<>();
        for (ConfiguredClass c : entries) {
            list.add(Json.map("class", c.className().replace('/', '.'),
                    "file", c.file(), "line", c.line(), "key", c.key()));
        }
        return Json.map("entries", list, "filesRead", filesRead);
    }
}
