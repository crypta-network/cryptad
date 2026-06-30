package network.crypta.platform.api;

import java.util.Locale;
import java.util.Objects;

/** Support phase for the published Platform API stable compatibility window. */
public enum PlatformApiCompatibilityWindowStatus {
  /** Active beta compatibility support window. */
  BETA("beta"),

  /** Stable non-beta compatibility support window. */
  STABLE("stable"),

  /** Replaced by a newer documented stable baseline. */
  SUPERSEDED("superseded"),

  /** No longer supported for new release certification. */
  EXPIRED("expired");

  private final String jsonValue;

  PlatformApiCompatibilityWindowStatus(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the stable JSON value used in contract snapshots and release reports.
   *
   * @return lowercase support-phase value
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses a support-phase value from a contract snapshot.
   *
   * @param value JSON support-phase value
   * @return matching status
   * @throws IllegalArgumentException when the value is unsupported
   */
  public static PlatformApiCompatibilityWindowStatus parse(String value) {
    String normalized =
        Objects.requireNonNull(value, "supportPhase").trim().toLowerCase(Locale.ROOT);
    for (PlatformApiCompatibilityWindowStatus status : values()) {
      if (status.jsonValue.equals(normalized)) {
        return status;
      }
    }
    throw new IllegalArgumentException(
        "unsupported Platform API compatibility-window status: " + value);
  }
}
