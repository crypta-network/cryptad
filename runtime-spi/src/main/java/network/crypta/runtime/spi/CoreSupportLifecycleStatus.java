package network.crypta.runtime.spi;

import java.util.Arrays;
import java.util.Optional;

/**
 * Closed lifecycle vocabulary for published Stable 1.0 core builds.
 *
 * <p>The values describe support for one release build, not the health of the update signing key.
 * In particular, {@link #REVOKED} is an authenticated build-policy decision and must never be used
 * to trigger update-key blow or revocation behavior. Callers should preserve the wire value when
 * presenting status through JSON or operator diagnostics.
 *
 * <p>Normal lifecycle transitions follow the declaration order from {@link #CURRENT_STABLE} through
 * {@link #END_OF_SUPPORT}. {@code REVOKED} is a separate terminal security state.
 */
public enum CoreSupportLifecycleStatus {
  /**
   * The single authenticated release-chain tip that receives normal maintenance and security
   * support.
   */
  CURRENT_STABLE("current-stable"),

  /** A superseded build that remains in its full compatible-maintenance window. */
  SUPPORTED_MAINTENANCE("supported-maintenance"),

  /** A build for which only security-relevant fixes remain committed. */
  SECURITY_FIXES_ONLY("security-fixes-only"),

  /** A build with an active deprecation notice and an authenticated upgrade path. */
  DEPRECATED("deprecated"),

  /** A build outside ordinary maintenance and security-fix commitments. */
  END_OF_SUPPORT("end-of-support"),

  /** A build declared unsafe by a separately authorized build-revocation transition. */
  REVOKED("revoked");

  private final String wireValue;

  CoreSupportLifecycleStatus(String wireValue) {
    this.wireValue = wireValue;
  }

  /**
   * Returns the exact descriptor and Platform API spelling for this status.
   *
   * @return closed lowercase wire value used by lifecycle descriptors and local JSON snapshots
   */
  public String wireValue() {
    return wireValue;
  }

  /**
   * Parses one exact lifecycle wire value without accepting aliases or case folding.
   *
   * <p>Unknown spellings remain empty so descriptor validation can fail closed instead of silently
   * treating a future or malformed value as supported.
   *
   * @param value exact value read from an authenticated lifecycle descriptor
   * @return matching status, or an empty result when the value is outside the closed vocabulary
   */
  public static Optional<CoreSupportLifecycleStatus> fromWireValue(String value) {
    return Arrays.stream(values()).filter(status -> status.wireValue.equals(value)).findFirst();
  }
}
