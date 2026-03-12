package network.crypta.node;

import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.Key;

/**
 * Aggregates the core request metadata needed to construct a {@link RequestSender}.
 *
 * @param key target key for the request
 * @param pubKey optional SSK public key used for verification
 * @param htl hop-to-live value for routing
 * @param uid unique request identifier
 * @param tag request-scoped coordination tag
 * @param node owning node
 * @param source originating peer, or {@code null} for local requests
 */
public record RequestSenderContext(
    Key key,
    DSAPublicKey pubKey,
    short htl,
    long uid,
    RequestTag tag,
    Node node,
    PeerNode source) {}
