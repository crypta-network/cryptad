package network.crypta.clients.fcp;

/**
 * Flags describing how {@link ClientGetGetterFactory} should configure a getter.
 *
 * <p>The flags capture whether a request should discard data, record a Binary Blob stream, and
 * allocate persistent buckets. They are kept together to reduce parameter counts while preserving
 * the existing getter wiring behavior.
 *
 * @param discardData whether payload bytes should be discarded when Binary Blob recording is
 *     disabled.
 * @param binaryBlob whether to record a Binary Blob stream instead of regular output data.
 * @param persistenceForever whether the request persists across restarts for bucket selection.
 */
public record ClientGetGetterFlags(
    boolean discardData, boolean binaryBlob, boolean persistenceForever) {}
