package network.crypta.clients.fcp;

import network.crypta.client.InsertContext;

/**
 * Bundles cache, redundancy, and compatibility tuning parameters for FCP inserts.
 *
 * <p>This record groups the insert context settings that tune cache usage, redundancy behavior, and
 * encoding compatibility. Callers typically build an instance alongside a behavior options record
 * and pass both into {@code FcpInsertOptions} so a single request can initialize an {@link
 * network.crypta.client.InsertContext} with consistent values. The record is immutable and
 * thread-safe because its components are final and have no mutable substructure; it does not
 * validate or normalize inputs, leaving default selection and range enforcement to higher layers.
 * This preserves legacy behavior and makes construction inexpensive.
 *
 * <ul>
 *   <li>Controls whether client cache writes and cacheable forks are permitted.
 *   <li>Captures redundancy factors for single-block and splitfile header inserts.
 *   <li>Records the compatibility mode used for splitfile encoding decisions.
 * </ul>
 *
 * @param canWriteClientCache whether client cache writes are permitted; {@code true} allows
 *     downstream logic to store insert results in the client cache.
 * @param forkOnCacheable whether to fork insert contexts when blocks become cacheable; {@code true}
 *     signals that cacheability may trigger a context fork.
 * @param compressorDescriptor optional compressor descriptor string; may be {@code null} to use
 *     default codec selection in downstream components.
 * @param extraInsertsSingleBlock redundancy factor for single-block inserts; the value is stored as
 *     provided and interpreted by downstream scheduling logic.
 * @param extraInsertsSplitfileHeaderBlock redundancy factor for splitfile header blocks; stored as
 *     provided and used to tune header reliability.
 * @param compatibilityMode compatibility mode guiding splitfile encoding parameters; expected to be
 *     non-null and preserved without normalization.
 */
public record FcpInsertTuningOptions(
    boolean canWriteClientCache,
    boolean forkOnCacheable,
    String compressorDescriptor,
    int extraInsertsSingleBlock,
    int extraInsertsSplitfileHeaderBlock,
    InsertContext.CompatibilityMode compatibilityMode) {}
