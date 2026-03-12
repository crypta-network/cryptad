package network.crypta.node;

/**
 * Exception indicating that a blocking synchronous send exceeded the allowed wait time.
 *
 * <p>Thrown when a component (for example, {@link PeerNode}) enqueues a message for transmission
 * and blocks waiting for an acknowledgement, but the acknowledgement does not arrive within the
 * configured timeout. Callers typically abort or reschedule the operation according to higher-level
 * policy. This class carries no additional state and is immutable.
 *
 * <p>Contrast with {@link network.crypta.io.xfer.WaitedTooLongException}, which is used when a
 * caller waits for bandwidth throttling/permit clearance and the wait itself times out before a
 * send is attempted.
 *
 * @author toad
 */
public class SyncSendWaitedTooLongException extends Exception {}
