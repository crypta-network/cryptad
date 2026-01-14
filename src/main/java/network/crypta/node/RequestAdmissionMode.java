package network.crypta.node;

/**
 * Encapsulates request admission mode flags used by load management decisions.
 *
 * @param isLocal whether the request originated locally
 * @param isInsert whether the request is an insert
 * @param isSSK whether the request targets an SSK key
 * @param isOfferReply whether the request is an offer reply
 * @param realTimeFlag whether the request uses real-time scheduling
 */
public record RequestAdmissionMode(
    boolean isLocal, boolean isInsert, boolean isSSK, boolean isOfferReply, boolean realTimeFlag) {}
