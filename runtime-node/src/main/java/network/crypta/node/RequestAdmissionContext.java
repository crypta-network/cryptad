package network.crypta.node;

/**
 * Captures request admission inputs used by {@link NodeStats}.
 *
 * @param canAcceptAnyway whether to allow periodic acceptance despite ping delays
 * @param hasInStore whether the requested block is already in the datastore
 * @param preferInsert whether inserts should be favored over requests
 * @param source source peer or {@code null} for local requests
 * @param tag request tag associated with this admission decision
 * @param mode request mode flags
 */
public record RequestAdmissionContext(
    boolean canAcceptAnyway,
    boolean hasInStore,
    boolean preferInsert,
    PeerNode source,
    UIDTag tag,
    RequestAdmissionMode mode) {

  /** Builds a context matching the legacy {@code shouldRejectRequest} parameters. */
  public static RequestAdmissionContext of(
      boolean canAcceptAnyway,
      boolean isInsert,
      boolean isSSK,
      boolean isLocal,
      boolean isOfferReply,
      PeerNode source,
      boolean hasInStore,
      boolean preferInsert,
      boolean realTimeFlag,
      UIDTag tag) {
    return new RequestAdmissionContext(
        canAcceptAnyway,
        hasInStore,
        preferInsert,
        source,
        tag,
        new RequestAdmissionMode(isLocal, isInsert, isSSK, isOfferReply, realTimeFlag));
  }

  public boolean isLocal() {
    return mode.isLocal();
  }

  public boolean isInsert() {
    return mode.isInsert();
  }

  public boolean isSSK() {
    return mode.isSSK();
  }

  public boolean isOfferReply() {
    return mode.isOfferReply();
  }

  public boolean realTimeFlag() {
    return mode.realTimeFlag();
  }

  public void markAccepted() {
    if (tag != null) {
      tag.setAccepted();
    }
  }
}
