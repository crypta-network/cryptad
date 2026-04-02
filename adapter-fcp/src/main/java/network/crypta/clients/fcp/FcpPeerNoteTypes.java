package network.crypta.clients.fcp;

/**
 * Defines peer-note type identifiers used by FCP message parsing and response generation.
 *
 * <p>This package-private helper lets ordinary FCP message classes refer to stable peer-note type
 * values without importing daemon-owned classes solely for numeric constants. The values are kept
 * deliberately small and local to the package because they are part of the FCP wire contract rather
 * than a broader runtime SPI. Parity tests pin these constants to the daemon's current values, so
 * drift is caught during test runs instead of during protocol handling.
 *
 * <p>The class is immutable and stateless. Callers such as {@code ListPeerNotesMessage} and {@code
 * ModifyPeerNote} use it only when validating requests or constructing outbound note messages.
 */
final class FcpPeerNoteTypes {
  /**
   * Numeric peer-note type used for a node operator's private darknet comment.
   *
   * <p>This is the only peer-note type currently consumed by the ordinary FCP peer-note messages in
   * this package. It maps to the private comment text returned by {@code PeerNote} responses and
   * accepted by note-modification requests.
   */
  static final int PRIVATE_DARKNET_COMMENT = 1;

  /** Prevents instantiation of this constants-only helper type. */
  private FcpPeerNoteTypes() {}
}
