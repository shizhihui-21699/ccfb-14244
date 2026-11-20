package dev.reachmap.graph;

import dev.reachmap.model.Edge;
import dev.reachmap.model.MethodId;
import dev.reachmap.model.EdgeKind;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The reachability graph.
 *
 * <p>Edges are kept in insertion order per node so that when several proofs exist the report can
 * prefer the shortest/most confident one deterministically. The graph also keeps a reverse index
 * so that a path from any entry can be reconstructed without a full re-search.
 */
public final class ReachGraph {

    private final Map<MethodId, List<Edge>> out = new ConcurrentHashMap<>();
    private final Map<String, Edge> edgeIndex = new HashMap<>();
    private final Set<MethodId> nodes = new LinkedHashSet<>();
    private int truncated = 0;

    public synchronized boolean addNode(MethodId m, int maxNodes) {
        if (nodes.contains(m)) return false;
        if (nodes.size() >= maxNodes) { truncated++; return false; }
        nodes.add(m);
        return true;
    }

    public synchronized boolean addEdge(Edge e) {
        String key = e.from().owner() + "#" + e.from().name() + e.from().desc()
                + "->" + e.to().owner() + "#" + e.to().name() + e.to().desc();
        if (edgeIndex.containsKey(key)) return false;
        edgeIndex.put(key, e);
        out.computeIfAbsent(e.from(), k -> new ArrayList<>()).add(e);
        nodes.add(e.from());
        nodes.add(e.to());
        return true;
    }

    public boolean hasEdge(MethodId from, MethodId to) {
        String key = from.owner() + "#" + from.name() + from.desc()
                + "->" + to.owner() + "#" + to.name() + to.desc();
        return edgeIndex.containsKey(key);
    }

    public List<Edge> edgesFrom(MethodId m) {
        return out.getOrDefault(m, List.of());
    }

    public Set<MethodId> nodes() { return Collections.unmodifiableSet(nodes); }

    public int edgeCount() { return edgeIndex.size(); }

    public int truncatedNodes() { return truncated; }

    // ------------------------------------------------------------------ search

    /** Result of a reachability search: predecessor chain per reached method. */
    public static final class SearchResult {
        private final Map<MethodId, Edge> predecessor = new HashMap<>();
        private final Map<MethodId, Integer> depth = new HashMap<>();
        private final Set<MethodId> reached;
        private final boolean truncated;

        SearchResult(Map<MethodId, Edge> pred, Map<MethodId, Integer> depth, Set<MethodId> reached, boolean truncated) {
            this.predecessor.putAll(pred);
            this.depth.putAll(depth);
            this.reached = reached;
            this.truncated = truncated;
        }

        public boolean reached(MethodId m) { return reached.contains(m); }
        public Set<MethodId> reachedNodes() { return Collections.unmodifiableSet(reached); }
        public int depthOf(MethodId m) { return depth.getOrDefault(m, -1); }
        public boolean truncated() { return truncated; }

        /** Reconstructs the proof path to {@code target}, or null if unreached. */
        public List<Edge> pathTo(MethodId target) {
            if (!reached.contains(target)) return null;
            LinkedList<Edge> path = new LinkedList<>();
            MethodId cur = target;
            Edge e;
            int guard = 0;
            while ((e = predecessor.get(cur)) != null && guard++ < 100_000) {
                path.addFirst(e);
                cur = e.from();
            }
            return path;
        }

        public MethodId entryOf(MethodId target) {
            List<Edge> p = pathTo(target);
            if (p == null || p.isEmpty()) return target;
            return p.get(0).from();
        }
    }

    /**
     * Best-evidence search from the roots.
     *
     * <p>Reachability alone is not the goal: the report has to print the <em>strongest</em> proof
     * available. A path whose weakest hop is an exact call is a qualitatively different claim from
     * one that ends in a speculative interface dispatch. So the search is a lexicographic
     * Dijkstra over (worst confidence rank on the path, path length): it finds, for each method,
     * the path with the strongest weakest link, breaking ties by shortest.
     *
     * <p>All nodes reached within the depth bound are returned regardless of edge confidence, since
     * even a speculative path is evidence that a method may be reachable (that difference is what
     * separates REACHABLE from UNKNOWN).
     */
    public SearchResult bestPaths(Collection<MethodId> roots, int maxDepth, long maxVisited) {
        Map<MethodId, Edge> pred = new HashMap<>();
        Map<MethodId, Integer> depth = new HashMap<>();
        Map<MethodId, EdgeKind.Confidence> cost = new HashMap<>();
        Set<MethodId> reached = new LinkedHashSet<>();
        boolean truncated = false;

        // Priority: (confidence rank, depth). Deterministic tie-break by insertion sequence.
        record Node(MethodId m, int confRank, int d, long seq) {}
        PriorityQueue<Node> pq = new PriorityQueue<>(Comparator
                .comparingInt(Node::confRank).thenComparingInt(Node::d).thenComparingLong(Node::seq));
        long seq = 0;
        for (MethodId r : roots) {
            if (cost.containsKey(r)) continue;
            cost.put(r, EdgeKind.Confidence.EXACT);
            depth.put(r, 0);
            reached.add(r);
            pq.add(new Node(r, 0, 0, seq++));
        }

        while (!pq.isEmpty()) {
            Node cur = pq.poll();
            MethodId m = cur.m();
            // Stale entry: a better path was found after this was queued.
            if (cost.get(m).rank() != cur.confRank() || depth.get(m) != cur.d()) continue;
            if (cur.d() >= maxDepth) { truncated = true; continue; }
            for (Edge e : edgesFrom(m)) {
                MethodId to = e.to();
                EdgeKind.Confidence newCost = EdgeKind.Confidence.worst(
                        cur.confRank() == 0 ? EdgeKind.Confidence.EXACT : cost.get(m), e.confidence());
                int newDepth = cur.d() + 1;
                EdgeKind.Confidence old = cost.get(to);
                if (old != null) {
                    int oldDepth = depth.get(to);
                    boolean better = newCost.rank() < old.rank()
                            || (newCost.rank() == old.rank() && newDepth < oldDepth);
                    if (!better) continue;
                } else {
                    if (cost.size() >= maxVisited) { truncated = true; continue; }
                }
                cost.put(to, newCost);
                depth.put(to, newDepth);
                pred.put(to, e);
                reached.add(to);
                pq.add(new Node(to, newCost.rank(), newDepth, seq++));
            }
        }
        return new SearchResult(pred, depth, reached, truncated);
    }

    /**
     * BFS from one or more roots, bounded by depth.
     *
     * <p>Used for the reachable-set snapshot; {@link #bestPaths} is used when a proof path has to
     * be printed.
     */
    public SearchResult reachFrom(Collection<MethodId> roots, int maxDepth, long maxVisited) {
        Map<MethodId, Edge> pred = new HashMap<>();
        Map<MethodId, Integer> depth = new HashMap<>();
        Set<MethodId> reached = new LinkedHashSet<>();
        ArrayDeque<MethodId> queue = new ArrayDeque<>();
        boolean truncated = false;

        for (MethodId r : roots) {
            if (depth.putIfAbsent(r, 0) == null) queue.add(r);
            reached.add(r);
        }
        while (!queue.isEmpty()) {
            MethodId cur = queue.poll();
            int d = depth.get(cur);
            if (d >= maxDepth) { truncated = true; continue; }
            for (Edge e : edgesFrom(cur)) {
                MethodId to = e.to();
                if (depth.containsKey(to)) continue;
                if (depth.size() >= maxVisited) { truncated = true; break; }
                depth.put(to, d + 1);
                pred.put(to, e);
                reached.add(to);
                queue.add(to);
            }
        }
        return new SearchResult(pred, depth, reached, truncated);
    }

    /** Worst confidence on a path, together with the dominating edge. */
    public static EdgeKind.Confidence pathConfidence(List<Edge> path, Edge[] weakestOut) {
        EdgeKind.Confidence worst = EdgeKind.Confidence.EXACT;
        Edge weakest = null;
        for (Edge e : path) {
            if (e.confidence().rank() > worst.rank()) { worst = e.confidence(); weakest = e; }
        }
        if (weakestOut != null && weakestOut.length > 0) weakestOut[0] = weakest;
        return worst;
    }
}
