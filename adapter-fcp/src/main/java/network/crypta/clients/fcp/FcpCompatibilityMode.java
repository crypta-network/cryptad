package network.crypta.clients.fcp;

import java.util.HashMap;
import java.util.Map;

/**
 * Adapter-owned compatibility mode used by FCP insert and status surfaces.
 *
 * <p>This detached enum mirrors the compatibility codes and names that the FCP layer exposes
 * without tying the adapter to the live daemon {@code InsertContext} enum. The values are stable
 * across persistence and wire encoding because they retain the same symbolic names and numeric
 * codes as the runtime modes they replace on the adapter boundary.
 *
 * <p>Two pseudo-values retain their historical meaning. {@link #COMPAT_UNKNOWN} represents “nothing
 * useful has been learned yet,” which is mainly relevant for status aggregation, while {@link
 * #COMPAT_CURRENT} means “use this build's current default concrete mode” and therefore must be
 * normalized with {@link #intern()} before persistence or bridge round-tripping. All other enum
 * constants are concrete, stable compatibility modes that can safely cross the adapter boundary and
 * be written into a persistent request state.
 */
public enum FcpCompatibilityMode {
  /** No concrete compatibility information is available yet. */
  COMPAT_UNKNOWN((short) 0),

  /** Use the current build's latest concrete compatibility mode. */
  COMPAT_CURRENT((short) 1),

  /** Historical compatibility mode matching the exact 1250-era segment layout. */
  COMPAT_1250_EXACT((short) 2),

  /** Historical compatibility mode matching the broader 1250 behavior. */
  COMPAT_1250((short) 3),

  /** Historical compatibility mode introduced with the 1251 splitfile behavior. */
  COMPAT_1251((short) 4),

  /** Historical compatibility mode introduced with the 1255 splitfile behavior. */
  COMPAT_1255((short) 5),

  /** Historical compatibility mode that introduced the newer CHK encryption behavior. */
  COMPAT_1416((short) 6),

  /** Historical compatibility mode that records top-level compression metadata explicitly. */
  COMPAT_1468((short) 7);

  /** Lookup table used to resolve persisted numeric codes back into enum constants. */
  private static final Map<Short, FcpCompatibilityMode> MODES_BY_CODE = new HashMap<>();

  static {
    for (FcpCompatibilityMode mode : values()) {
      if (MODES_BY_CODE.put(mode.code, mode) != null) {
        throw new IllegalStateException("Duplicated compatibility mode code: " + mode.code);
      }
    }
  }

  /** Default compatibility mode for new inserts when the client omits one. */
  public static final FcpCompatibilityMode COMPAT_DEFAULT = COMPAT_CURRENT;

  /** Stable numeric code preserved for persistence and FCP status reporting. */
  private final short code;

  FcpCompatibilityMode(short code) {
    this.code = code;
  }

  /**
   * Returns the numeric code associated with this mode.
   *
   * @return stable compatibility code used in persistence and FCP status reporting.
   */
  public short code() {
    return code;
  }

  /**
   * Returns the newest concrete compatibility mode known to this build.
   *
   * @return latest compatibility mode.
   */
  public static FcpCompatibilityMode latest() {
    return COMPAT_1468;
  }

  /**
   * Normalizes {@link #COMPAT_CURRENT} into a stable concrete mode.
   *
   * @return concrete compatibility mode suitable for persistence.
   */
  public FcpCompatibilityMode intern() {
    return this == COMPAT_CURRENT ? latest() : this;
  }

  /**
   * Resolves a numeric compatibility code back into the detached enum.
   *
   * @param code numeric compatibility code.
   * @return matching detached compatibility mode.
   */
  public static FcpCompatibilityMode byCode(short code) {
    FcpCompatibilityMode mode = MODES_BY_CODE.get(code);
    if (mode == null) {
      throw new IllegalArgumentException("Unknown compatibility mode code: " + code);
    }
    return mode;
  }

  /**
   * Indicates whether the supplied numeric code maps to a known detached compatibility mode.
   *
   * @param code numeric compatibility code.
   * @return {@code true} if the code is known.
   */
  @SuppressWarnings("unused")
  public static boolean hasCode(short code) {
    return MODES_BY_CODE.containsKey(code);
  }
}
