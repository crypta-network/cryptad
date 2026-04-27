package network.crypta.platform.appdist;

import java.util.Locale;
import java.util.Objects;

/**
 * Restart policy declared by an app bundle manifest.
 *
 * <p>The policy is intentionally small for the local AppHost runtime. It is signed as part of the
 * bundle manifest, parsed by appdist, and consumed by AppHost after installation. The value does
 * not describe a service manager, operating-system sandbox, or durable supervisor. It only tells
 * the current daemon session whether a failed child process may be relaunched automatically.
 *
 * <p>Restart limits and backoff are carried as separate manifest fields so policy selection remains
 * easy to audit in signed bundle metadata. Existing apps default to {@link #NEVER}, which preserves
 * the pre-hardening behavior unless an app author explicitly opts into bounded failure restarts.
 */
public enum AppRestartPolicy {
  /**
   * Never restart the app automatically after process exit.
   *
   * <p>This is the default for manifests that omit {@code app.restart.policy}. It keeps operator
   * control simple: a clean exit, crash, explicit stop, or accepted update leaves the app stopped
   * until a caller starts it again.
   */
  NEVER("never"),

  /**
   * Restart only after a non-zero process exit, up to the declared attempt limit.
   *
   * <p>This policy is process based. It does not perform HTTP health checks or app-defined probes,
   * and it never restarts after a clean zero exit or an explicit operator stop.
   */
  ON_FAILURE("on-failure");

  private final String manifestValue;

  AppRestartPolicy(String manifestValue) {
    this.manifestValue = manifestValue;
  }

  /**
   * Returns the manifest value for this policy.
   *
   * <p>The returned string is the canonical token stored in {@code cryptad-app.properties}. It is
   * lower-case ASCII and stable for signing, manifest generation, and diagnostics.
   *
   * @return lower-case manifest policy value suitable for serialized bundle metadata
   */
  @SuppressWarnings("unused")
  public String manifestValue() {
    return manifestValue;
  }

  /**
   * Parses an optional manifest policy value.
   *
   * <p>The parser accepts surrounding whitespace and case differences but does not accept aliases.
   * A missing value maps to {@link #NEVER}, matching the runtime default for existing apps. Invalid
   * values fail during manifest parsing so unsigned or misspelled restart behavior cannot be
   * silently interpreted later by AppHost.
   *
   * @param rawValue raw manifest value, or {@code null} when the manifest omits the field
   * @return parsed restart policy used by appdist and AppHost runtime code
   * @throws IllegalArgumentException if the value is not one of the supported policy tokens
   */
  public static AppRestartPolicy parseManifestValue(String rawValue) {
    if (rawValue == null) {
      return NEVER;
    }
    String normalized =
        Objects.requireNonNull(rawValue, "rawValue").trim().toLowerCase(Locale.ROOT);
    return switch (normalized) {
      case "never" -> NEVER;
      case "on-failure" -> ON_FAILURE;
      default -> throw new IllegalArgumentException("unsupported app.restart.policy: " + rawValue);
    };
  }
}
