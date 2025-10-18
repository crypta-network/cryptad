/**
 * Plugin-safe abstractions shared between plugins and the core node.
 *
 * <p>This package contains interfaces and a limited number of supporting classes that plugins may
 * implement or use, and that are also consumed by other parts of the node. Examples include data
 * containers such as {@code Bucket}. The design goal is to expose only the capabilities required by
 * plugins while preserving clear, enforceable boundaries with the core.
 *
 * <p>Design principles:
 *
 * <ul>
 *   <li><b>Least privilege:</b> APIs here must not expose more functionality than necessary, and
 *       must not enable privilege escalation by plugin code.
 *   <li><b>Minimal surface:</b> prefer small, focused interfaces. Implementations may reside
 *       elsewhere and should be replaceable.
 *   <li><b>Stable contracts:</b> compatibility for plugin usage is a priority; behavioral details
 *       are documented on the individual types.
 * </ul>
 *
 * <p>Threading, lifecycle, and error-handling guarantees (including any checked exceptions) are
 * documented on each type or method where relevant.
 */
package network.crypta.support.api;
