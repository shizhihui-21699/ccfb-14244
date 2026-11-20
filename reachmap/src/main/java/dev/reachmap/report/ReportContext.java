package dev.reachmap.report;

import dev.reachmap.analysis.Finding;
import dev.reachmap.analysis.Uncertainty;
import dev.reachmap.load.ClassPath;
import dev.reachmap.model.EntryPoint;

import java.util.List;

/** Everything a report renderer needs, passed as one immutable bundle. */
public record ReportContext(
        String projectName,
        String generatedAt,
        ClassPath classPath,
        List<EntryPoint> entries,
        List<Finding> findings,
        List<Uncertainty> uncertainties,
        int graphNodes,
        int graphEdges,
        int graphTruncated,
        double analysisSeconds,
        String toolVersion) {
}
