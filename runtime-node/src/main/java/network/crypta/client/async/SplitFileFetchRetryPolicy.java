package network.crypta.client.async;

/**
 * Captures retry and cooldown policy values persisted for splitfile fetch recovery.
 *
 * <p>This record groups retry-related settings so persistence helpers can pass a single parameter
 * object when encoding or decoding the on-disk layout. Values are stored as-is; callers are
 * responsible for applying any validation rules or special semantics such as {@code -1} meaning
 * unlimited retries.
 *
 * <ul>
 *   <li>Limits non-fatal retries with {@code maxRetries}.
 *   <li>Defines how often cooldowns occur via {@code cooldownTries}.
 *   <li>Controls cooldown duration with {@code cooldownLength}.
 * </ul>
 *
 * @param maxRetries maximum retry count persisted for future resume logic
 * @param cooldownTries number of retry attempts before cooldown applies
 * @param cooldownLength cooldown duration in milliseconds for retry scheduling
 */
public record SplitFileFetchRetryPolicy(int maxRetries, int cooldownTries, long cooldownLength) {}
