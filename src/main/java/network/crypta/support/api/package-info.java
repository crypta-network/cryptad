/**
 * Public support abstractions shared across node subsystems.
 *
 * <p>This package contains interfaces and a limited number of supporting classes consumed by
 * multiple parts of the node. Examples include data containers such as {@code Bucket}. The design
 * goal is to expose only the capabilities required by cross-subsystem callers while preserving
 * clear, enforceable boundaries with the core.
 *
 * <p>Design principles:
 *
 * <ul>
 *   <li><b>Least privilege:</b> APIs here must not expose more functionality than necessary.
 *   <li><b>Minimal surface:</b> prefer small, focused interfaces. Implementations may reside
 *       elsewhere and should be replaceable.
 *   <li><b>Stable contracts:</b> compatibility for callers is a priority; behavioral details are
 *       documented on the individual types.
 * </ul>
 *
 * <p>Threading, lifecycle, and error-handling guarantees (including any checked exceptions) are
 * documented on each type or method where relevant.
 */
package network.crypta.support.api;
