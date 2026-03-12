package network.crypta.client.async;

/**
 * Options controlling persistence and scheduling for block-level inserts.
 *
 * <p>This record is a lightweight container that mirrors constructor flags used by single-block
 * inserters. It performs no validation and stores values verbatim.
 *
 * @param persistent whether the insert is persistent across restarts
 * @param realTimeFlag whether to schedule the insert as real-time
 * @param freeData whether to free the source bucket on terminal completion
 * @param extraInserts number of additional successful insert attempts beyond the first
 */
public record BlockInsertOptions(
    boolean persistent, boolean realTimeFlag, boolean freeData, int extraInserts) {}
