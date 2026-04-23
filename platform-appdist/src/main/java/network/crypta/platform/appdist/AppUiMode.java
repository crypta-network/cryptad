package network.crypta.platform.appdist;

import java.util.Locale;
import java.util.Objects;

/**
 * Browser UI ownership mode declared by an app bundle manifest.
 *
 * <p>The mode tells AppHost, Platform API summaries, and HTTP adapters how to interpret {@code
 * app.ui.entry} without coupling bundle signing to one transport implementation. It is part of the
 * normalized manifest model: parsers either read the explicit {@code app.ui.mode} property or infer
 * a compatible value from the entry shape.
 *
 * <p>The inference rules preserve existing first-party manifests. An absent entry means {@link
 * #NONE}; an absolute same-origin local path such as {@code /app/node/#queue} means {@link
 * #SHELL_PANEL}; and a relative entry means {@link #STATIC}. Static entries remain inside the
 * signed bundle and are served later through app-owned routes such as {@code /apps/{appId}/}.
 */
public enum AppUiMode {
  /**
   * The app does not expose a browser UI.
   *
   * <p>Manifests in this mode must omit {@code app.ui.entry}. API summaries expose {@code null}
   * links so shells show only lifecycle controls. This is the inferred mode for older manifests
   * that never declared UI metadata.
   */
  NONE("none"),

  /**
   * The app opens an existing same-origin shell route.
   *
   * <p>This keeps current first-party apps compatible with entries such as {@code
   * /app/node/#queue}. The entry must be an absolute local path; external URLs are not part of the
   * v1 app UI contract and are rejected during manifest normalization.
   */
  SHELL_PANEL("shell-panel"),

  /**
   * The app owns static browser files inside its installed bundle.
   *
   * <p>Static entries are normalized relative paths beneath the immutable installed bundle root.
   * The legacy HTTP adapter serves them under {@code /apps/{appId}/}, and bundle structure
   * validation checks that the declared entry is a regular file covered by the signed payload.
   */
  STATIC("static");

  private final String manifestValue;

  AppUiMode(String manifestValue) {
    this.manifestValue = manifestValue;
  }

  /**
   * Returns the manifest/API spelling for this mode.
   *
   * <p>The returned value is stable external text. Manifest parsing, AppHost environment variables,
   * and Platform API JSON summaries all use this spelling instead of enum names.
   *
   * @return lower-case manifest value used in properties files and JSON summaries
   */
  public String manifestValue() {
    return manifestValue;
  }

  /**
   * Parses one optional {@code app.ui.mode} value.
   *
   * <p>The method trims whitespace and compares mode names case-insensitively. A {@code null} value
   * is not an error because callers need to apply backward-compatible inference from {@code
   * app.ui.entry}. A blank present value is an error because it is ambiguous and should not
   * silently change app launch behavior.
   *
   * @param value raw manifest property value; {@code null} means no explicit mode was declared
   * @return parsed UI mode, or {@code null} when the mode is absent
   * @throws IllegalArgumentException if the value is blank or not one of the supported mode names
   */
  public static AppUiMode parseManifestValue(String value) {
    if (value == null) {
      return null;
    }
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("app.ui.mode must not be blank");
    }
    for (AppUiMode mode : values()) {
      if (Objects.equals(mode.manifestValue, normalized)) {
        return mode;
      }
    }
    throw new IllegalArgumentException("unsupported app.ui.mode: " + value);
  }
}
