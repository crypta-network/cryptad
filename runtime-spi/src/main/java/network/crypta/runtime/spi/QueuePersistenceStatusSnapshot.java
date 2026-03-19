package network.crypta.runtime.spi;

import java.io.File;

/**
 * Captures the queue-persistence support state needed by the HTTP queue pages.
 *
 * <p>This record is the detached data shape returned by {@link
 * QueueSupportPort#persistenceStatus()} while the queue support pages are being migrated off direct
 * daemon access. It carries only the state that the legacy HTTP layer still needs to decide which
 * existing support page to render: whether the node is awaiting the master password, whether
 * shutdown is already in progress, and the persistence path details shown on the final
 * persistence-broken page.
 *
 * <p>The snapshot is immutable and intentionally limited to JDK types. Callers should treat it as a
 * point-in-time view rather than a live handle into daemon state. When {@code awaitingPassword} or
 * {@code stopping} is {@code true}, the path fields may be absent because the queue pages should
 * continue to short-circuit to the password or shutdown page without dereferencing persistence-file
 * state.
 *
 * @param awaitingPassword {@code true} when the node is currently waiting for the master password
 * @param stopping {@code true} when shutdown is in progress
 * @param persistentTempDir persistent temp directory shown on the legacy persistence-broken page;
 *     may be {@code null} when {@code awaitingPassword} or {@code stopping} is {@code true}
 * @param databasePath database path shown on the legacy persistence-broken page; may be {@code
 *     null} when {@code awaitingPassword} or {@code stopping} is {@code true}
 * @see QueueSupportPort
 */
public record QueuePersistenceStatusSnapshot(
    boolean awaitingPassword, boolean stopping, File persistentTempDir, String databasePath) {}
