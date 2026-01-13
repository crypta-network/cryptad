package network.crypta.io.xfer;

import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.PeerContext;
import network.crypta.support.Ticker;

/**
 * Carries the shared services and per-transfer inputs needed to send a single block to a peer.
 *
 * <p>This record is a lightweight, immutable bundle that keeps the block transmitter wiring
 * explicit. Callers populate it once, pass it into transfer setup, and then treat it as a read-only
 * state for the life of the transfer. The record does not perform work itself; it simply groups
 * together the core messaging, scheduling, and accounting objects alongside the block metadata and
 * peer identity. Invariants are established by the producer (for example, the block and counters
 * must be consistent with each other), and consumers assume they are stable for the duration of a
 * transfer attempt.
 *
 * <p>Instances are typically created just before constructing a {@link BlockTransmitter} and are
 * not reused across unrelated transfers. Concurrency safety depends on the referenced objects: the
 * record itself is immutable, but any stateful collaborators may have their own threading rules.
 *
 * <ul>
 *   <li>Collects all inputs required to initiate block transmission.
 *   <li>Preserves the logical identity of the transfer via the UID and peer context.
 *   <li>Exposes byte accounting and real-time behavior flags to downstream stages.
 * </ul>
 *
 * @param messageCore message dispatcher used to send or receive transfer messages during this run
 * @param ticker timing source for scheduling retries and time-based callbacks in the transfer
 * @param peer destination peer context that identifies the remote endpoint for the transfer
 * @param uid unique transfer identifier shared across logs and protocol messages for correlation
 * @param block partially received block metadata that describes packet sizing and progress
 * @param byteCounter counter that tracks transfer bytes and supports aggregated accounting
 * @param realTime {@code true} to prioritize low latency scheduling, {@code false} for bulk mode
 * @see BlockTransmitter
 */
public record BlockTransferContext(
    MessageCore messageCore,
    Ticker ticker,
    PeerContext peer,
    long uid,
    PartiallyReceivedBlock block,
    ByteCounter byteCounter,
    boolean realTime) {}
