/**
 * Command-line tools bundled with the Crypta node distribution.
 *
 * <p>This package contains small, standalone entry points intended to be invoked from the command
 * line (for example with {@code java -cp ... network.crypta.tools.AddRef}). Unlike the long-running
 * node daemon, these utilities typically perform a narrow task and then exit: importing or
 * transforming data, validating or rewriting local files, or assisting with developer and operator
 * workflows. They are designed to be script-friendly rather than a stable, embeddable library API.
 *
 * <p>Most tools follow a simple lifecycle: parse arguments, perform the required file/network I/O,
 * report a concise status message, and terminate with an appropriate process exit code. Each
 * invocation is self-contained and generally has no shared mutable state, so thread-safety is
 * typically not a concern unless a tool explicitly uses concurrency internally.
 *
 * <p><b>Notable tools:</b>
 *
 * <ul>
 *   <li>{@link network.crypta.tools.AddRef} — imports a peer reference into a running node
 *       (commonly used on Windows for handling {@code .fref} files).
 *   <li>{@link network.crypta.tools.MergeSFS} — merges SimpleFieldSet documents for maintenance and
 *       troubleshooting workflows.
 *   <li>{@link network.crypta.tools.CleanupTranslations} — normalizes translation property files in
 *       the source tree.
 * </ul>
 *
 * @see network.crypta.tools.AddRef
 * @see network.crypta.tools.MergeSFS
 * @see network.crypta.tools.CleanupTranslations
 */
package network.crypta.tools;
