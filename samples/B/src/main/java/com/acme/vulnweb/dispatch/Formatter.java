package com.acme.vulnweb.dispatch;

/**
 * Interface implemented exactly once, and the implementation is constructed only deep inside a
 * helper reached late in the graph.
 *
 * <p>This exists to pin down a traversal-order bug: if dispatch narrowing runs before the
 * implementation's `new` is seen, the interface call would appear to have no target and a real
 * path would be dropped. The analyzer pre-scans application `new` instructions so the answer does
 * not depend on which method the worklist happened to expand first.
 */
public interface Formatter {
    String format(String input);
}
