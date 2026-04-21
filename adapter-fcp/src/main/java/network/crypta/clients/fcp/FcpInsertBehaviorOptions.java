package network.crypta.clients.fcp;

/**
 * Bundles behavior flags and scheduling hints for FCP inserts.
 *
 * <p>This record captures a compact set of booleans and limits that describe how an insert request
 * should behave when it is routed through the FCP pipeline. Callers typically create an instance
 * alongside a tuning options record and pass both into {@link FcpInsertOptions} so the insert
 * context can be initialized consistently for file and directory requests. The record is immutable
 * and thread-safe because its components are final and have no mutable substructure. It performs no
 * validation or normalization; the values are preserved exactly as supplied so protocol parsing and
 * higher-level logic remain responsible for defaults and constraints.
 *
 * <ul>
 *   <li>Captures request-local behavior such as early encoding and local-only constraints.
 *   <li>Represents scheduling intent through the real-time flag.
 *   <li>Records retry limits and USK datehint behavior without interpretation.
 * </ul>
 *
 * @param getCHKOnly whether to compute the CHK without persisting blocks; {@code true} limits the
 *     insert to key derivation only.
 * @param dontCompress whether compression should be disabled for the insert; {@code true} bypasses
 *     codec selection in downstream logic.
 * @param localRequestOnly whether the insert should remain on the local node only; {@code true}
 *     avoids network propagation by policy.
 * @param maxRetries maximum retries before failing the insert; the value is stored as provided and
 *     may follow sentinel conventions used elsewhere.
 * @param consecutiveRnfsCountAsSuccess optional request-local RNF-as-success threshold; {@code
 *     null} keeps the runtime default.
 * @param earlyEncode whether encoding should begin before all data is received; {@code true} favors
 *     lower latency for streaming inserts.
 * @param realTimeFlag whether to schedule the insert in real-time queues; {@code true} requests low
 *     latency queueing when supported.
 * @param ignoreUSKDatehints whether USK datehints should be ignored during insert; {@code true}
 *     bypasses datehint optimizations in the insert pipeline.
 * @see FcpInsertOptions
 */
public record FcpInsertBehaviorOptions(
    boolean getCHKOnly,
    boolean dontCompress,
    boolean localRequestOnly,
    int maxRetries,
    Integer consecutiveRnfsCountAsSuccess,
    boolean earlyEncode,
    boolean realTimeFlag,
    boolean ignoreUSKDatehints) {}
