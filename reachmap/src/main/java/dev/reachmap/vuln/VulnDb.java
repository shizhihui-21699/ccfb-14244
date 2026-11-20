package dev.reachmap.vuln;

import dev.reachmap.util.Json;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Loads vulnerabilities from a JSON file (ReachMap's own format). */
public final class VulnDb {

    private final List<Vulnerability> vulnerabilities = new ArrayList<>();

    public static VulnDb load(Path p) throws IOException {
        VulnDb db = new VulnDb();
        if (p == null || !Files.isRegularFile(p)) return db;
        Object root = Json.parse(Files.readString(p));
        Map<String, Object> obj = Json.obj(root);
        for (Object o : Json.arr(obj.get("vulnerabilities"))) {
            Map<String, Object> v = Json.obj(o);
            List<Vulnerability.Sink> sinks = new ArrayList<>();
            for (Object so : Json.arr(v.get("sinks"))) {
                Map<String, Object> s = Json.obj(so);
                sinks.add(new Vulnerability.Sink(
                        Json.str(s, "class", ""),
                        Json.str(s, "method", ""),
                        Json.str(s, "note", null)));
            }
            db.vulnerabilities.add(new Vulnerability(
                    Json.str(v, "id", "UNKNOWN"),
                    Json.str(v, "title", ""),
                    Json.str(v, "severity", "HIGH"),
                    Json.str(v, "artifact", Json.str(v, "artifactId", "unknown")),
                    Json.str(v, "groupId", ""),
                    Json.str(v, "artifactId", Json.str(v, "artifact", "unknown")),
                    Json.str(v, "vulnerableRange", ""),
                    Json.str(v, "fixedVersion", null),
                    List.copyOf(sinks),
                    Json.str(v, "description", ""),
                    Json.str(v, "reference", null)));
        }
        return db;
    }

    public static VulnDb of(List<Vulnerability> vulns) {
        VulnDb db = new VulnDb();
        db.vulnerabilities.addAll(vulns);
        return db;
    }

    public List<Vulnerability> all() { return vulnerabilities; }

    /** Vulnerabilities whose artifact matches a dependency artifact label (substring match). */
    public List<Vulnerability> forArtifact(String artifact) {
        List<Vulnerability> out = new ArrayList<>();
        if (artifact == null) return out;
        String a = artifact.toLowerCase();
        for (Vulnerability v : vulnerabilities) {
            String va = v.artifactId() == null ? "" : v.artifactId().toLowerCase();
            if (!va.isEmpty() && a.contains(va)) out.add(v);
        }
        return out;
    }
}
