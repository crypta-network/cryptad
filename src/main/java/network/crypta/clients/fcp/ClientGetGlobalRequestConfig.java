package network.crypta.clients.fcp;

import java.io.File;

/**
 * Immutable configuration for constructing a persistent global {@link ClientGet}.
 *
 * <p>The record groups the validated inputs needed to create a global-queue GET request. Callers
 * assemble one instance after parsing FCP inputs and deriving defaults from the runtime, then hand
 * it to {@link ClientGetFactory} for the actual request construction. Keeping these values in a
 * single record makes the factory signature smaller without widening the package API surface or
 * changing how request validation works.
 *
 * <p>The instance is a pure data carrier. It does not normalize or lazily compute anything after
 * construction, so the contained values should already reflect the final policy decisions for the
 * request, including persistence scope, DDA-planned return routing, retry limits, and scheduling
 * hints.
 *
 * @param dsOnly whether the fetch is restricted to local datastore lookups only
 * @param ignoreDS whether the datastore should be skipped in favor of network retrieval
 * @param filterData whether fetched content should be filtered before delivery
 * @param maxSplitfileRetries maximum retry count applied to splitfile block fetches
 * @param maxNonSplitfileRetries maximum retry count applied to non-splitfile fetches
 * @param maxOutputLength upper bound, in bytes, for the returned payload and temp data
 * @param returnType delivery mode describing whether data is returned directly, discarded, or
 *     written to disk
 * @param persistRebootOnly whether the request should survive only until the next node restart
 * @param identifier stable request identifier used for queue ownership and collision checks
 * @param verbosity bitmask controlling which FCP progress messages are emitted to clients
 * @param prioClass scheduler priority class used when the request is started
 * @param returnFilename target file for disk-return requests, or {@code null} when not applicable
 * @param charset optional charset hint preserved for compatibility with legacy inputs
 * @param writeToClientCache whether successful fetches may populate the client cache
 * @param realTimeFlag whether the request should use real-time scheduling behavior
 * @param binaryBlob whether the request should emit Binary Blob output instead of ordinary data
 */
record ClientGetGlobalRequestConfig(
    boolean dsOnly,
    boolean ignoreDS,
    boolean filterData,
    int maxSplitfileRetries,
    int maxNonSplitfileRetries,
    long maxOutputLength,
    ClientGet.ReturnType returnType,
    boolean persistRebootOnly,
    String identifier,
    int verbosity,
    short prioClass,
    File returnFilename,
    String charset,
    boolean writeToClientCache,
    boolean realTimeFlag,
    boolean binaryBlob) {}
