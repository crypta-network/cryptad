/**
 * Runtime-owned diagnostics seams and façade types for operator visibility.
 *
 * <p>This package defines the runtime-level diagnostics entry points that expose information about
 * a running node without committing higher layers to any specific UI or transport. It contains the
 * façade and small service interfaces that connect daemon-backed sampling to the rest of the
 * runtime. Concrete rendering remains outside this package, so diagnostics data can be reused by
 * multiple operator-facing surfaces.
 *
 * <p>Keeping diagnostics here makes the boundary explicit for later extraction work: the runtime
 * owns collection and publication of diagnostic states, while adapters remain responsible for
 * formatting, transport, and presentation.
 */
package network.crypta.runtime.diagnostics;
