package network.crypta.platform.appdist;

import java.util.Locale;
import java.util.Objects;

/**
 * Process sandbox mode declared by an app bundle manifest.
 *
 * <p>The mode is signed as part of {@code cryptad-app.properties} so AppHost can make launch-time
 * decisions from authenticated metadata. The values intentionally describe requested runtime
 * policy, not a guarantee that a specific host can provide hard operating-system isolation. AppHost
 * reports the actual support level separately at runtime through its sandbox status model.
 *
 * <p>This enum lives in {@code platform-appdist} because bundle signing and verification need to
 * parse the manifest without depending on AppHost internals. The values are therefore stable
 * manifest tokens rather than implementation classes. AppHost providers may support only a subset
 * of the modes on a given host. Runtime status reports the actual outcome for operators: no
 * isolation, best-effort launch hygiene, an unsupported mode, or a future enforced sandbox. Unknown
 * values fail parsing so signed bundles cannot silently request behavior that this node does not
 * understand.
 */
public enum AppSandboxMode {
  /**
   * Run the app with the normal local child-process launch path.
   *
   * <p>This is the default for existing manifests. It provides no operating-system sandbox
   * isolation beyond AppHost's existing launch hygiene and token/path redaction boundaries. API and
   * Shell surfaces should show this mode plainly as unsandboxed rather than presenting it as a
   * security feature.
   */
  NONE("none"),

  /**
   * Request the AppHost restricted-process launch path.
   *
   * <p>The v1 implementation is conservative and best-effort. It can apply and report AppHost
   * process-launch hygiene, but it must not be described as a container, chroot, jail, seccomp
   * filter, or equivalent hard sandbox unless a future provider actually enforces those controls. A
   * manifest can combine this mode with {@code sandbox.required=true} to require provider support,
   * but the runtime status still distinguishes best-effort from enforced isolation.
   */
  RESTRICTED_PROCESS("restricted-process"),

  /**
   * Reserve a future WebAssembly runtime mode.
   *
   * <p>PR-206 parses this value so manifests can be validated consistently, but the default host
   * has no WASM provider and therefore reports the mode as unsupported unless a future embedding
   * supplies one explicitly. Keeping the token in the signed manifest grammar lets tooling reject
   * misspellings now while leaving runtime execution to a later provider.
   */
  WASM_PREVIEW("wasm-preview");

  private final String manifestValue;

  AppSandboxMode(String manifestValue) {
    this.manifestValue = manifestValue;
  }

  /**
   * Returns the manifest/API spelling for this sandbox mode.
   *
   * <p>The returned value is the only spelling that should be written to {@code
   * cryptad-app.properties} or exposed in Platform API JSON. It is intentionally lower-case and
   * hyphenated so app manifests, catalog metadata, and operator-facing status output use the same
   * vocabulary.
   *
   * @return lower-case stable manifest token for this sandbox mode
   */
  public String manifestValue() {
    return manifestValue;
  }

  /**
   * Parses an optional {@code sandbox.mode} value.
   *
   * <p>A missing value maps to {@link #NONE} for backward compatibility with existing app
   * manifests. Present blank or unknown values fail manifest validation. Parsing is
   * case-insensitive, but the normalized value returned by {@link #manifestValue()} remains the
   * canonical spelling for signatures, API responses, and Web Shell display.
   *
   * @param rawValue raw manifest property value, or {@code null} when the key is absent
   * @return parsed sandbox mode using {@link #NONE} for omitted manifest values
   * @throws IllegalArgumentException if a present value is blank or not one of the supported tokens
   */
  public static AppSandboxMode parseManifestValue(String rawValue) {
    if (rawValue == null) {
      return NONE;
    }
    String normalized =
        Objects.requireNonNull(rawValue, "rawValue").trim().toLowerCase(Locale.ROOT);
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("sandbox.mode must not be blank");
    }
    for (AppSandboxMode mode : values()) {
      if (Objects.equals(mode.manifestValue, normalized)) {
        return mode;
      }
    }
    throw new IllegalArgumentException("unsupported sandbox.mode: " + rawValue);
  }
}
