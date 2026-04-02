package network.crypta.node;

/**
 * Immutable insert routing option bundle derived from optional submessages.
 *
 * <p>Each flag mirrors a dedicated submessage and defaults to {@link Node} constants when the
 * submessage is absent. The values are captured once per request to keep the scheduling logic
 * simple and avoid repeated message parsing.
 *
 * @param preferInsert true when the peer prefers insert routing over fetch-friendly behavior
 * @param ignoreLowBackoff true when low-backoff suppression should be bypassed
 * @param forkOnCacheable true when cacheable inserts are allowed to fork
 */
public record InsertRoutingOptions(
    boolean preferInsert, boolean ignoreLowBackoff, boolean forkOnCacheable) {}
