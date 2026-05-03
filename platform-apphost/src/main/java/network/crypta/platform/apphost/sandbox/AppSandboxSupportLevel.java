package network.crypta.platform.apphost.sandbox;

/**
 * Runtime support level actually applied for a requested app sandbox policy.
 *
 * <p>This enum is the main guard against overstating sandbox guarantees. The requested {@code
 * sandbox.mode} comes from the manifest, while this value reports what the host can provide for a
 * stopped app summary or a concrete process launch. API clients and Web Shell labels should display
 * this value rather than inferring safety from the requested mode alone.
 *
 * <p>The values are ordered conceptually rather than by strength in code. {@link #BEST_EFFORT}
 * means AppHost applied local launch hygiene but no hard containment; only {@link #ENFORCED} should
 * be used by a provider that can point to real operating-system or runtime isolation.
 */
public enum AppSandboxSupportLevel {
  /**
   * No sandbox isolation is active.
   *
   * <p>This is the expected support level for {@code sandbox.mode=none}. Operators should read it
   * as an explicit unsandboxed status, not as an error condition.
   */
  NONE("none"),

  /**
   * AppHost applied conservative process-launch hygiene but no hard OS containment.
   *
   * <p>The default restricted-process provider uses this level. It can report sanitized environment
   * and app-scoped directory checks, but it must not be described as container, seccomp, chroot,
   * jail, or WASM isolation.
   */
  BEST_EFFORT("best-effort"),

  /**
   * The requested sandbox mode is not supported by the current provider set.
   *
   * <p>Optional unsupported requests may still launch with this status and warnings. Required
   * unsupported requests should fail before process start.
   */
  UNSUPPORTED("unsupported"),

  /**
   * A provider has applied real enforced sandbox controls.
   *
   * <p>The Linux bubblewrap provider uses this value for wrapped restricted-process launch plans.
   * Other providers should set it only when they can enforce concrete operating-system or runtime
   * restrictions and document those restrictions separately.
   */
  ENFORCED("enforced");

  /** Stable lower-case token exposed through Platform API JSON. */
  private final String manifestValue;

  AppSandboxSupportLevel(String manifestValue) {
    this.manifestValue = manifestValue;
  }

  /**
   * Returns the stable JSON/API spelling for this support level.
   *
   * <p>The returned value is intended for public status surfaces. It is lower-case and hyphenated
   * where needed so app summaries, runtime status, and Web Shell labels share one vocabulary.
   *
   * @return lower-case support-level token for API and Shell status output
   */
  public String manifestValue() {
    return manifestValue;
  }
}
