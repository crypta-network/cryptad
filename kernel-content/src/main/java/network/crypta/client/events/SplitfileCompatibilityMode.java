package network.crypta.client.events;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Defines the detached compatibility-mode values carried by {@link
 * SplitfileCompatibilityModeEvent}.
 *
 * <p>This enum preserves the stable symbolic names and numeric codes that the runtime layer already
 * uses when it reasons about splitfile compatibility, but it keeps those values in a leaf-safe form
 * that {@code :kernel-content} can own directly. Use it when an event, adapter boundary, or other
 * compile-neutral surface needs to report compatibility choices without exposing the live-runtime
 * {@code InsertContext} model.
 *
 * <p>The values are intentionally small and stable. Each constant carries the short code used for
 * boundary translation and persistence-facing reporting, while runtime code remains responsible for
 * mapping from the live compatibility state into this detached representation. The enum itself is
 * immutable and thread-safe. Callers should treat it as a boundary value object rather than as a
 * place to add runtime policy.
 *
 * <ul>
 *   <li>Responsibility: provide detached, compile-neutral splitfile compatibility vocabulary.
 *   <li>Stability: retain the existing symbolic names and short codes used across boundaries.
 *   <li>Scope: model event payload values, not runtime policy or compatibility selection rules.
 * </ul>
 *
 * @see SplitfileCompatibilityModeEvent
 */
public enum SplitfileCompatibilityMode {
  /**
   * Indicates that no concrete compatibility information is available yet.
   *
   * <p>Producers typically use this when they have not learned enough about the splitfile layout to
   * announce a real lower or upper bound. It is primarily useful for progress and status surfaces
   * that need to distinguish "unknown" from a concrete historical mode.
   */
  COMPAT_UNKNOWN((short) 0),

  /**
   * Indicates that the current build's latest concrete compatibility mode should be used.
   *
   * <p>This remains a detached mirror of the runtime-side pseudo-current value. Boundary code may
   * still transport it as a stable enum constant, but runtime code should resolve it to a concrete
   * mode before it affects splitfile layout decisions that must remain reproducible.
   */
  COMPAT_CURRENT((short) 1),

  /**
   * Represents the exact 1250-era segment layout.
   *
   * <p>This mode preserves the older behavior where segments contain exactly 128 data blocks and
   * 128 check blocks, with the check-block count matching the data-block count. It is the most
   * specific detached representation of the pre-1250 exact layout.
   */
  COMPAT_1250_EXACT((short) 2),

  /**
   * Represents the broader 1250-or-earlier compatibility behavior.
   *
   * <p>In this mode, segments may contain up to 128 data blocks and 128 check blocks, with the
   * check-block count constrained to {@code <=} the data-block count. Use this detached value when
   * callers need the historical 1250 behavior without requiring the exact-layout variant above.
   */
  COMPAT_1250((short) 3),

  /**
   * Represents the 1251/1252/1253 compatibility behavior.
   *
   * <p>This mode captures the first even-splitting behavior used after the 1250 variants, including
   * the capped extra-check handling for smaller segment sizes. It remains a concrete detached mode
   * that can cross event and adapter boundaries safely.
   */
  COMPAT_1251((short) 4),

  /**
   * Represents the 1255 compatibility behavior.
   *
   * <p>This mode captures the second-stage even-splitting update together with the related hash
   * behavior changes introduced at that time. It is a concrete historical mode rather than a
   * placeholder or policy flag.
   */
  COMPAT_1255((short) 5),

  /**
   * Represents the 1416 compatibility behavior.
   *
   * <p>This detached value marks the splitfile mode associated with the newer CHK encryption
   * behavior. Event consumers can use it to report or merge the selected compatibility window
   * without importing the runtime insert context directly.
   */
  COMPAT_1416((short) 6),

  /**
   * Represents the 1468 compatibility behavior.
   *
   * <p>This mode records the splitfile behavior that includes explicit top-level compression and
   * compatibility metadata. It is currently the newest concrete detached mode defined by this enum.
   */
  COMPAT_1468((short) 7);

  /**
   * Lookup table used by {@link #byCode(short)}.
   *
   * <p>The map is built once during class initialization and then wrapped as unmodifiable, so
   * lookup stays deterministic for the lifetime of the JVM. Keys are the stable short codes carried
   * across detached event boundaries.
   */
  private static final Map<Short, SplitfileCompatibilityMode> MODES_BY_CODE;

  static {
    HashMap<Short, SplitfileCompatibilityMode> modesByCode = new HashMap<>();
    for (SplitfileCompatibilityMode mode : values()) {
      if (modesByCode.put(mode.code, mode) != null) {
        throw new IllegalStateException("Duplicated compatibility mode code: " + mode.code);
      }
    }
    MODES_BY_CODE = Collections.unmodifiableMap(modesByCode);
  }

  /**
   * Stable numeric code preserved for event delivery and boundary translations.
   *
   * <p>The code is part of the detached compatibility contract used by runtime-to-kernel and
   * kernel-to-adapter mapping logic. It is final, read-only, and intended for lookup or reporting
   * rather than for arithmetic or ordinal-style comparisons in callers.
   */
  public final short code;

  /**
   * Creates one detached compatibility-mode constant with its stable short code.
   *
   * @param code stable short code associated with this enum constant.
   */
  SplitfileCompatibilityMode(short code) {
    this.code = code;
  }

  /**
   * Resolves a stable numeric compatibility code back into the detached enum.
   *
   * <p>Use this helper at module boundaries where code-based translation is safer than relying on
   * enum declaration order or symbolic-name parsing. The lookup accepts only codes known to this
   * build. Callers that receive an unknown code should treat that as a version or boundary mismatch
   * rather than silently guessing.
   *
   * @param code stable short compatibility code received from a boundary translation path or stored
   *     event payload.
   * @return the detached compatibility mode associated with {@code code}; never {@code null} for a
   *     known value.
   * @throws IllegalArgumentException if {@code code} does not map to any detached compatibility
   *     mode known to this build.
   */
  public static SplitfileCompatibilityMode byCode(short code) {
    SplitfileCompatibilityMode mode = MODES_BY_CODE.get(code);
    if (mode == null) {
      throw new IllegalArgumentException("Unknown compatibility mode code: " + code);
    }
    return mode;
  }
}
