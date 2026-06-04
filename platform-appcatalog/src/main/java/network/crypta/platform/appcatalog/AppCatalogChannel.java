package network.crypta.platform.appcatalog;

import java.util.Locale;

/**
 * Release channel declared by a signed app catalog entry.
 *
 * <p>The channel is authenticated catalog metadata that tells clients how the publisher intends an
 * artifact to be handled in production. Catalog readers use it for display, release-certification
 * evidence, and app-update policy decisions. The value is intentionally small and stable because it
 * is serialized into signed catalog properties, Platform API responses, and developer-tool
 * descriptors.
 *
 * <p>A channel is not a trust shortcut. Install and update flows still verify the catalog
 * signature, artifact digest, signed bundle, trusted review receipt policy, compatibility metadata,
 * and AppHost constraints before accepting an app. Automatic update policy may allow only a subset
 * of these channels; explicit operator actions can still inspect and stage available non-stable
 * entries when the surrounding service permits that workflow.
 *
 * <p>The enum is immutable and thread-safe. Use {@link #parse(String, String)} for catalog or query
 * input so diagnostics use the same bounded single-line validation as other catalog sidecars, and
 * use {@link #catalogValue()} when writing catalog files or JSON payloads.
 */
public enum AppCatalogChannel {
  /**
   * Production-safe app release channel.
   *
   * <p>Stable entries are the default for omitted legacy metadata and the default automatic-update
   * channel. Publishers should use this value only after the bundle, review evidence, and
   * compatibility metadata are suitable for ordinary node operators.
   */
  STABLE("stable"),

  /**
   * Public beta channel for operator-selected preview builds.
   *
   * <p>Beta entries are visible catalog candidates, but automatic updates include them only when
   * the local policy allows beta automation. This keeps preview releases available for explicit
   * testing without silently moving stable-only nodes onto pre-release app builds.
   */
  BETA("beta"),

  /**
   * Frequently changing development channel for explicit operator testing.
   *
   * <p>Nightly entries are intended for fast-moving integration or live-network validation work.
   * Operators and clients should expect these artifacts to change more often than stable or beta
   * releases and should treat automatic use as an opt-in policy decision.
   */
  NIGHTLY("nightly"),

  /**
   * Retained metadata for apps that should not be treated as ordinary update candidates.
   *
   * <p>Deprecated entries remain in catalogs so clients can explain an app's retirement or
   * migration path. Update policy deliberately excludes this channel from automatic processing even
   * if an operator supplies it in an allowed-channel set.
   */
  DEPRECATED("deprecated");

  private final String catalogValue;

  AppCatalogChannel(String catalogValue) {
    this.catalogValue = catalogValue;
  }

  /**
   * Parses a strict catalog channel token from catalog text or API input.
   *
   * <p>The parser applies the catalog sidecar single-line and length checks before matching the
   * token case-insensitively against the supported serialized values. Callers pass the original
   * field name so validation failures can point at the catalog property or query parameter that
   * supplied the value. The returned enum is the normalized representation used by catalog entries,
   * update policy, and JSON serializers.
   *
   * @param value catalog or API text such as {@code stable}, {@code beta}, or {@code nightly}
   * @param fieldName field name used in diagnostics for malformed or unsupported input
   * @return matching normalized channel for policy checks and serialization
   * @throws AppCatalogException if the token is blank, multi-line, too long, or unsupported
   */
  public static AppCatalogChannel parse(String value, String fieldName) {
    String normalized =
        AppCatalogSidecars.requireBoundedSingleLine(
                value, fieldName, AppCatalogSidecars.INVALID_CATALOG_ENTRY, 32)
            .toLowerCase(Locale.ROOT);
    for (AppCatalogChannel channel : values()) {
      if (channel.catalogValue.equals(normalized)) {
        return channel;
      }
    }
    throw AppCatalogSidecars.invalidEntry("unsupported " + fieldName + ": " + value);
  }

  /**
   * Returns the lower-case catalog and API token for this channel.
   *
   * <p>The returned value is the stable wire representation written into catalog properties and
   * surfaced through Platform API JSON. It is independent of the Java enum constant name so callers
   * do not need to duplicate lower-casing rules or depend on {@link #name()}.
   *
   * @return stable serialized channel value used in catalogs and API responses
   */
  public String catalogValue() {
    return catalogValue;
  }
}
