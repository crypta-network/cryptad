package network.crypta.io.comm;

/**
 * Marker interface for transport handlers that send and receive protocol messages.
 *
 * <p>Implementations encapsulate a specific transport (for example, UDP) and typically manage both
 * inbound and outbound traffic. A node may create multiple handler instances for different
 * configurations such as ports, peers, or cryptographic contexts. Implementations define their own
 * lifecycle and may expose additional transport‑specific APIs via subinterfaces.
 *
 * <p>Thread‑safety: Unless otherwise stated by the implementation, callers should assume that
 * instances are thread‑safe and may be invoked concurrently by the networking stack.
 *
 * <p>Example implementation: the UDP socket handler currently kept in the runtime-node leaf.
 *
 * @author toad
 */
public interface SocketHandler {}
