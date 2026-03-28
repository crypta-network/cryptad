/**
 * Provides the runtime-owned internal seam for the remaining legacy queue administration helpers.
 *
 * <p>The types in this package deliberately stay small and focused on the queue diagnostics,
 * support, and mutation work still owned by {@code network.crypta.runtime.admin}. They let the
 * admin adapters depend on a narrow queue backend view without importing protocol-specific FCP
 * request-status classes and without widening {@code runtime-spi} while the broader extraction is
 * still in flight.
 *
 * <p>The package has two responsibilities:
 *
 * <ul>
 *   <li>define the backend seam used by runtime-admin to query and mutate the global queue
 *   <li>define minimal status views that preserve the legacy admin behavior without leaking FCP
 *       types across the runtime boundary
 * </ul>
 */
package network.crypta.runtime.admin.queue;
