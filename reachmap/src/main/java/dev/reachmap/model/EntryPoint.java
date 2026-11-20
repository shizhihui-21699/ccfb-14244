package dev.reachmap.model;

import java.util.ArrayList;
import java.util.List;

/** A discovered entry point from which reachability is explored. */
public final class EntryPoint {
    private final MethodId method;
    private final EntryKind kind;
    private final String route;          // HTTP path / job name, may be null
    private final String httpMethods;    // GET, POST, ... for endpoints
    private final String note;
    private final List<String> taintedParams = new ArrayList<>(); // parameter names holding attacker input
    private final List<Integer> taintedParamIndexes = new ArrayList<>();
    private final String sourceClass;

    public EntryPoint(MethodId method, EntryKind kind, String route, String httpMethods, String note, String sourceClass) {
        this.method = method;
        this.kind = kind;
        this.route = route;
        this.httpMethods = httpMethods;
        this.note = note;
        this.sourceClass = sourceClass;
    }

    public MethodId method() { return method; }
    public EntryKind kind() { return kind; }
    public String route() { return route; }
    public String httpMethods() { return httpMethods; }
    public String note() { return note; }
    public String sourceClass() { return sourceClass; }
    public List<String> taintedParams() { return taintedParams; }
    public List<Integer> taintedParamIndexes() { return taintedParamIndexes; }

    public EntryPoint withTaintedParams(List<String> params) {
        taintedParams.addAll(params);
        return this;
    }

    public EntryPoint withTaintedParamIndexes(List<Integer> indexes) {
        taintedParamIndexes.addAll(indexes);
        return this;
    }

    public String label() {
        StringBuilder sb = new StringBuilder(kind.name());
        if (route != null) {
            sb.append(' ').append(route);
            if (httpMethods != null) sb.append(" [").append(httpMethods).append(']');
        }
        return sb.toString();
    }

    @Override
    public String toString() { return label() + " -> " + method.display(); }
}
