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
    boolean isLocal, boolean isInsert, boolean isSSK, boolean isOfferReply, boolean realTimeFlag) {

  /**
   * Create a mode using the flag order commonly used by request tracking APIs.
   *
   * @param isLocal whether the request originated locally
   * @param isSSK whether the request targets an SSK key
   * @param isInsert whether the request is an insert
   * @param isOfferReply whether the request is an offer reply
   * @param realTimeFlag whether the request uses real-time scheduling
   * @return a new {@link RequestAdmissionMode} with the supplied flags
   */
  public static RequestAdmissionMode of(
      boolean isLocal,
      boolean isSSK,
      boolean isInsert,
      boolean isOfferReply,
      boolean realTimeFlag) {
    return new RequestAdmissionMode(isLocal, isInsert, isSSK, isOfferReply, realTimeFlag);
  }

  /**
   * Create a mode from the properties of a {@link UIDTag}.
   *
   * @param tag tag providing request characteristics
   * @return a new {@link RequestAdmissionMode} describing the tag
   */
  public static RequestAdmissionMode fromTag(UIDTag tag) {
    return of(tag.wasLocal(), tag.isSSK(), tag.isInsert(), tag.isOfferReply(), tag.realTimeFlag);
  }
}
