package network.crypta.platform.devtools;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Named beta developer templates accepted by {@code crypta-app init --template}.
 *
 * <p>The enum is the CLI boundary between user-facing template names and the scaffold renderer.
 * Each value describes a staged static app bundle that can be validated, served by the mock dev
 * server, signed, packed, and published through the catalog tooling. Templates deliberately avoid
 * creating Gradle subprojects or touching a running node; generated apps remain plain staged
 * bundles. Default permissions are examples for the API surface demonstrated by the template, and
 * callers may extend them with repeatable {@code --permission} options when building a more
 * specific app.
 *
 * <p>The parsing contract is stable and case-insensitive for CLI input, while {@link #cliName()}
 * returns the canonical lower-case spelling used in help text, diagnostics, tests, and
 * documentation. Keep names conservative because they become part of the developer workflow.
 */
enum AppTemplateKind {
  /** Minimal static app equivalent to the pre-template scaffold. */
  STATIC_BASIC("static-basic"),

  /** Queue dashboard sample that reads and mutates queue entries through the browser SDK. */
  QUEUE_DASHBOARD("queue-dashboard"),

  /** Content publisher sample that creates insert requests through SDK helpers. */
  PUBLISHER("publisher"),

  /** Vault profile sample that uses safe mock identity/grant data through app-vault routes. */
  VAULT_PROFILE("vault-profile");

  /** Canonical lower-case CLI spelling for this template. */
  private final String cliName;

  /**
   * Creates one template kind.
   *
   * @param cliName stable lower-case name accepted by {@code crypta-app init --template}
   */
  AppTemplateKind(String cliName) {
    this.cliName = cliName;
  }

  /**
   * Parses one CLI template name.
   *
   * @param rawName user-supplied template name, or {@code null} for the default template
   * @return matching template kind
   * @throws IllegalArgumentException if the value does not name a supported template
   */
  static AppTemplateKind parse(String rawName) {
    if (rawName == null || rawName.isBlank()) {
      return STATIC_BASIC;
    }
    String normalized = rawName.trim().toLowerCase(Locale.ROOT);
    for (AppTemplateKind kind : values()) {
      if (kind.cliName.equals(normalized)) {
        return kind;
      }
    }
    throw new IllegalArgumentException(
        "unsupported app template: " + rawName + " (expected: " + supportedNames() + ")");
  }

  /**
   * Returns the stable CLI spelling.
   *
   * @return lower-case hyphenated template name
   */
  String cliName() {
    return cliName;
  }

  /**
   * Returns permissions that the template demonstrates by default.
   *
   * @return immutable permission list in manifest order
   */
  List<String> defaultPermissions() {
    return switch (this) {
      case STATIC_BASIC -> List.of();
      case QUEUE_DASHBOARD -> List.of("queue.read", "queue.write");
      case PUBLISHER -> List.of("content.insert", "queue.read", "queue.write");
      case VAULT_PROFILE -> List.of("vault.identities.read", "vault.identities.use");
    };
  }

  /**
   * Returns whether the generated manifest should accept experimental Platform API capabilities.
   *
   * @return {@code true} when the template's default permissions demonstrate experimental APIs
   */
  boolean experimentalCapabilitiesAccepted() {
    return this == VAULT_PROFILE;
  }

  /**
   * Returns a comma-separated list of supported template names for help and diagnostics.
   *
   * @return deterministic template name list
   */
  static String supportedNames() {
    return Arrays.stream(values()).map(AppTemplateKind::cliName).collect(Collectors.joining(", "));
  }
}
