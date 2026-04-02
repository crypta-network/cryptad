/**
 * Thread inspection and snapshot helpers used by the runtime diagnostics layer.
 *
 * <p>This package contains the concrete thread sampler plus the immutable snapshot records that
 * describe thread activity inside a running daemon. The code bridges JVM thread information and
 * node-local execution metadata into a reusable runtime representation that higher layers can poll
 * or export.
 *
 * <p>The package intentionally stops at the collection and modeling. It does not own HTTP
 * rendering, alert presentation, or endpoint-specific formatting, which keeps the thread
 * diagnostics boundary reusable for later kernel and adapter splits.
 */
package network.crypta.runtime.diagnostics.threads;
