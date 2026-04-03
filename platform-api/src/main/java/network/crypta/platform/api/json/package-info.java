/**
 * Small JSON encoding helpers for the Platform API.
 *
 * <p>This package owns the lightweight JSON writer and snapshot-to-JSON mappers used by {@code
 * :platform-api}. It intentionally supports only the data shapes required by the initial read-only
 * API surface, avoiding any new heavyweight serialization dependency.
 */
package network.crypta.platform.api.json;
