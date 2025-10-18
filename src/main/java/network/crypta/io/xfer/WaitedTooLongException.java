package network.crypta.io.xfer;

/**
 * Exception indicating that sending a throttled packet exceeded the allowed wait time.
 *
 * <p>Used by throttling/rate‑limit code to signal that the caller has waited long enough for a
 * permit or scheduling window and should stop the current send attempt. Callers typically abort,
 * reschedule, or drop the packet according to higher‑level policy. This class carries no additional
 * state.
 *
 * @author toad
 */
public class WaitedTooLongException extends Exception {}
