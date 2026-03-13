package network.crypta.compat;

/**
 * Compatibility value object describing forwarding progress or outcome for a requested port.
 *
 * <p>This record is used by forwarding-provider callbacks to report how confidently a mapping is
 * believed to be active. The status code follows legacy numeric semantics preserved from earlier
 * plugin-facing APIs, which allows existing adapters to continue reporting outcomes without
 * translation logic. In addition to the status code, the record can include a human-readable reason
 * and an externally mapped port number when the gateway assigns one.
 *
 * <p>The record is immutable and can be safely shared across threads. Consumers typically interpret
 * values using the provided constants and treat unrecognized codes conservatively.
 *
 * <ul>
 *   <li><b>Primary use:</b> communicate per-port forwarding confidence to alert/state logic.
 *   <li><b>Compatibility focus:</b> preserve historic success/failure code meanings.
 * </ul>
 *
 * @param status forwarding outcome code, typically one of the {@code *_SUCCESS}/{@code *_FAILURE}
 *     constants or {@link #IN_PROGRESS}
 * @param reasonString optional human-readable diagnostic text associated with the status
 * @param externalPort externally observed mapped port, if different from the requested port
 */
public record ForwardPortStatus(int status, String reasonString, int externalPort) {
  /** Legacy code indicating forwarding is definitely established. */
  public static final int DEFINITE_SUCCESS = 3;

  /** Legacy code indicating forwarding is likely established but not definitively verified. */
  public static final int PROBABLE_SUCCESS = 2;

  /** Legacy code indicating forwarding may be established but requires independent confirmation. */
  public static final int MAYBE_SUCCESS = 1;

  /** Legacy code indicating a forwarding attempt is still in progress. */
  public static final int IN_PROGRESS = 0;

  /** Legacy code indicating forwarding likely failed but could be transient. */
  public static final int PROBABLE_FAILURE = -1;

  /** Legacy code indicating forwarding definitively failed. */
  public static final int DEFINITE_FAILURE = -2;
}
