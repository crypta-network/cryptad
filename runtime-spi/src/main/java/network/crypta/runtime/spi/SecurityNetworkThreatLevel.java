package network.crypta.runtime.spi;

/**
 * Detached network threat levels exposed through the runtime SPI.
 *
 * <p>The values intentionally match the legacy daemon enum names exactly so existing HTTP form
 * payloads and localization key derivation can continue to use {@link #name()} without another
 * mapping layer in callers.
 */
public enum SecurityNetworkThreatLevel {
  /** Favor performance and permit opennet participation. */
  LOW,

  /** Default mixed posture with both opennet and darknet available. */
  NORMAL,

  /** Darknet-only posture with standard hardening. */
  HIGH,

  /** Most restrictive darknet-only posture. */
  MAXIMUM;

  /**
   * Parses a threat level from its exact enum name.
   *
   * @param value exact enum name, case-sensitive
   * @return parsed level or {@code null} when the value is invalid
   */
  public static SecurityNetworkThreatLevel parse(String value) {
    try {
      return SecurityNetworkThreatLevel.valueOf(value);
    } catch (IllegalArgumentException _) {
      return null;
    }
  }

  /**
   * Returns the levels that still permit Opennet participation.
   *
   * @return detached opennet-capable threat levels
   */
  public static SecurityNetworkThreatLevel[] opennetValues() {
    return new SecurityNetworkThreatLevel[] {LOW, NORMAL};
  }

  /**
   * Returns the levels that require darknet-only operation.
   *
   * @return detached darknet-only threat levels
   */
  public static SecurityNetworkThreatLevel[] darknetValues() {
    return new SecurityNetworkThreatLevel[] {HIGH, MAXIMUM};
  }
}
