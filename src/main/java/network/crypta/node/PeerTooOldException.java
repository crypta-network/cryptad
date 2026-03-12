package network.crypta.node;

import java.io.Serial;
import java.time.Instant;

/**
 * Exception indicating that a remote peer was rejected because its software build is older than the
 * minimum version supported by this node.
 *
 * <p>Instances include a human‑readable reason, the peer‑reported build number, and the
 * peer‑reported build date to aid diagnostics and logging. The {@linkplain #getMessage() message}
 * concatenates these details for convenience.
 */
public class PeerTooOldException extends Exception {
  @Serial private static final long serialVersionUID = 1L;

  /**
   * Human-readable explanation of why the peer is considered too old (e.g., below minimum build).
   */
  public final String reason;

  /** Peer-reported integer build number of the remote node. */
  public final int buildNumber;

  /**
   * Peer-reported build date. May be {@code null} when the date is unknown or not provided by the
   * remote peer.
   */
  public final Instant buildDate;

  /**
   * Constructs a new exception with contextual details about the outdated remote peer.
   *
   * @param reason human-readable explanation of the incompatibility
   * @param build peer-reported build number
   * @param d peer-reported build date; may be {@code null} if unavailable
   */
  public PeerTooOldException(final String reason, final int build, final Instant d) {
    super("Peer too old: " + reason + " from " + build + " at " + d);
    this.buildDate = d;
    this.buildNumber = build;
    this.reason = reason;
  }
}
