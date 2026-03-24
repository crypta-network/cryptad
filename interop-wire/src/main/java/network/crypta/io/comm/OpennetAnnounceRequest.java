package network.crypta.io.comm;

/**
 * Immutable metadata for an opennet announce request message.
 *
 * @param uid request identifier used to correlate responses
 * @param transferUID transfer identifier for the noderef payload
 * @param noderefLength unpadded noderef length in bytes
 * @param paddedLength padded transfer length in bytes
 * @param target target location in {@code [0.0, 1.0)}
 * @param htl hop-to-live value for routing
 */
public record OpennetAnnounceRequest(
    long uid, long transferUID, int noderefLength, int paddedLength, double target, short htl) {}
