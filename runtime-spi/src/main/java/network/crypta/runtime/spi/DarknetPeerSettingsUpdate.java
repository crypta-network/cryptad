package network.crypta.runtime.spi;

/**
 * Represents one optional update to darknet-only peer settings.
 *
 * <p>Each field is nullable. A {@code null} value means "leave the current setting unchanged",
 * allowing higher layers to preserve the legacy FCP semantics where missing or empty fields do not
 * alter the target peer.
 *
 * <p>The record deliberately models only the small set of darknet peer flags migrated in this PR.
 * It is a detached request value rather than a live view of the peer state. Callers are expected to
 * populate only the fields that were present in the original management request and then pass the
 * value to {@link PeerPort#updateDarknetPeer(String, DarknetPeerSettingsUpdate)}.
 *
 * @param disabled optional disabled flag update; {@code null} leaves the current disabled state
 *     unchanged
 * @param listenOnly optional listen-only flag update; {@code null} leaves the current setting
 *     unchanged
 * @param burstOnly optional burst-only flag update; {@code null} leaves the current setting
 *     unchanged
 * @param ignoreSourcePort optional source-port handling update; {@code null} leaves the current
 *     setting unchanged
 * @param allowLocalAddresses optional local-address allowance update; {@code null} leaves the
 *     current setting unchanged
 */
public record DarknetPeerSettingsUpdate(
    Boolean disabled,
    Boolean listenOnly,
    Boolean burstOnly,
    Boolean ignoreSourcePort,
    Boolean allowLocalAddresses) {
  /**
   * Returns whether this update carries no requested changes.
   *
   * <p>This is a structural check only. It does not inspect the current peer state, and it does not
   * infer whether applying the update would be a no-op for a specific peer instance.
   *
   * @return {@code true} when every field is {@code null}
   */
  public boolean isEmpty() {
    return disabled == null
        && listenOnly == null
        && burstOnly == null
        && ignoreSourcePort == null
        && allowLocalAddresses == null;
  }
}
