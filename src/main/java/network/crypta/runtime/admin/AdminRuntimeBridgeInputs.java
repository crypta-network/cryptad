package network.crypta.runtime.admin;

import network.crypta.runtime.admin.geoip.GeoIpCountryLookup;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;

/**
 * Carries the runtime-owned bridge inputs needed to assemble the admin runtime-port bundle.
 *
 * <p>{@link network.crypta.runtime.core.LegacyRuntimePorts} creates this record at the runtime
 * composition root after it has already chosen the concrete bridge factories for queue handling and
 * GeoIP lookup. {@link AdminRuntimePortsFactory} then consumes the record and wires the legacy
 * admin adapters without importing endpoint-owned factory entry points. That keeps the wiring
 * explicit while preserving the existing daemon-backed behavior for queue pages, queue mutations,
 * diagnostics, and connections-page country rendering.
 *
 * <p>The record is intentionally mechanical. It does not validate, normalize, cache, or lazily
 * resolve any of its members. Callers are expected to populate every component with the live seam
 * or port instance that should back one {@link AdminRuntimePortsBundle}. The record itself is
 * immutable and thread-safe, but the contained adapters remain live views over the mutable daemon
 * state.
 *
 * <ul>
 *   <li>Queue read and mutation seams stay grouped in one handoff object.
 *   <li>GeoIP lookup wiring stays explicit without widening {@code runtime-spi}.
 *   <li>Construction ownership stays in runtime core, not in {@code runtime.admin}.
 * </ul>
 *
 * @param queueAdminBackend queue backend seam used by diagnostics, support helpers, and generic
 *     queue mutations
 * @param queuePageBackend queue page seam used to render detached queue-page snapshots and exports
 * @param queueCompletionPort queue completion port that exposes the existing completion-oriented
 *     bridge behavior
 * @param queueDownloadPort queue download mutation port that preserves the current bridge behavior
 *     for downloads
 * @param queueInsertPort queue insert mutation port that preserves the current bridge behavior for
 *     inserts
 * @param geoIpCountryLookup GeoIP lookup seam used when rendering country information on the
 *     Connections page
 * @see AdminRuntimePortsFactory
 * @see network.crypta.runtime.core.LegacyRuntimePorts
 */
public record AdminRuntimeBridgeInputs(
    QueueAdminBackend queueAdminBackend,
    QueuePageBackend queuePageBackend,
    QueueCompletionPort queueCompletionPort,
    QueueDownloadPort queueDownloadPort,
    QueueInsertPort queueInsertPort,
    GeoIpCountryLookup geoIpCountryLookup) {}
