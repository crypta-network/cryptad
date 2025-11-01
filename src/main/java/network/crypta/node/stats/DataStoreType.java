package network.crypta.node.stats;

/**
 * Categorizes the high-level type of data store used by the node.
 *
 * <p>This enumeration is used by statistics, diagnostics, and administrative views to group and
 * label stores that share similar behavior and lifecycle characteristics. It abstracts over
 * implementation details and storage engines and focuses on how the store is expected to be used:
 * whether as a durable repository, a transient cache, a specialized policy-driven cache, or a
 * client-scoped store. The constants are stable, immutable descriptors and can be used safely for
 * aggregation keys, UI labels, or conditional logic in reporting.
 *
 * <p>All enum constants are thread-safe and carry no mutable state. They are suitable for use in
 * concurrent contexts and may be freely cached or shared. The classification is intentionally
 * minimal to avoid coupling node internals to the statistics model; additional per-store metadata
 * should be obtained from {@link DataStoreStats} or related metric views.
 *
 * <ul>
 *   <li>{@link #STORE} — durable, authoritative persistent storage.
 *   <li>{@link #CACHE} — transient cache with eviction and best-effort retention.
 *   <li>{@link #SLASHDOT} — specialized cache with custom aging/retention policy.
 *   <li>{@link #CLIENT} — client-scoped store for request or session-related data.
 * </ul>
 *
 * @see network.crypta.node.stats.DataStoreKeyType
 * @see network.crypta.node.stats.DataStoreStats
 * @author nikotyan
 */
public enum DataStoreType {
  /**
   * Durable, authoritative persistent storage for long-lived data and indexes.
   *
   * <p>Stores classified as {@code STORE} are typically the canonical source of truth for
   * content-addressed or identity-scoped data. They prioritize durability and integrity over
   * eviction and may employ validation and compaction routines. Reporting for these stores often
   * focuses on capacity utilization, on-disk size, and read/write performance over longer windows.
   */
  STORE,

  /**
   * Transient cache intended to accelerate reads or reduce load on authoritative stores.
   *
   * <p>Caches commonly implement size- or time-based eviction and do not guarantee retention. They
   * are best-effort and can be reconstructed from upstream sources when entries are missing.
   * Statistics for caches typically emphasize hit/miss ratios, eviction rates, and short-term
   * throughput rather than long-term durability metrics.
   */
  CACHE,

  /**
   * Specialized cache that applies a policy tailored for bursty access patterns.
   *
   * <p>Often used for smoothing sudden popularity spikes, these stores may rely on custom aging or
   * prioritization heuristics distinct from general-purpose caches. While still non-authoritative,
   * their behavior is tuned for specific traffic profiles, and statistics may highlight temporary
   * retention effectiveness and mitigation of hotspot amplification.
   */
  SLASHDOT,

  /**
   * Client-scoped store used for metadata, request coordination, or session-adjacent state.
   *
   * <p>Entries in client stores are generally smaller and more numerous, with lifecycles tied to
   * client activity rather than global network retention. They may be ephemeral or persisted for
   * recovery, depending on configuration. Metrics often surface queue sizes, callback counts, and
   * per-client access patterns.
   */
  CLIENT
}
