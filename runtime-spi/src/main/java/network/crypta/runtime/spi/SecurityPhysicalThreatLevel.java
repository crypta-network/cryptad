package network.crypta.runtime.spi;

/**
 * Detached physical threat levels exposed through the runtime SPI.
 *
 * <p>The values intentionally match the legacy daemon enum names exactly so existing HTTP form
 * payloads and localization key derivation can continue to use {@link #name()} without another
 * mapping layer in callers.
 */
public enum SecurityPhysicalThreatLevel {
  /** Do not encrypt local transient artifacts. */
  LOW,

  /** Encrypt temporary artifacts and centralize client-cache keys in {@code master.keys}. */
  NORMAL,

  /** Require a password to unlock {@code master.keys}. */
  HIGH,

  /** Use transient encryption and disable persistence-dependent features. */
  MAXIMUM;

  /**
   * Parses a threat level from its exact enum name.
   *
   * @param value exact enum name, case-sensitive
   * @return parsed level or {@code null} when the value is invalid
   */
  public static SecurityPhysicalThreatLevel parse(String value) {
    try {
      return SecurityPhysicalThreatLevel.valueOf(value);
    } catch (IllegalArgumentException _) {
      return null;
    }
  }
}
