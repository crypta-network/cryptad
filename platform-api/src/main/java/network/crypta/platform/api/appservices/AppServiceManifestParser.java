package network.crypta.platform.api.appservices;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.apphost.manifest.AppManifest;

/**
 * Parses optional app-service metadata from {@code cryptad-app.properties}.
 *
 * <p>The core AppHost manifest parser intentionally remains narrow; this parser reads only the
 * app-service extension keys after the core manifest has already identified the installed app. It
 * supports provider declarations under {@code app.services.provides} and consumer request
 * declarations under {@code app.services.requests}. Unknown properties are ignored so signed
 * manifests can carry app-service metadata without changing unrelated core fields.
 *
 * <p>All identifiers, aliases, scopes, contexts, and status-like values are normalized through the
 * same bounded token rules used by route inputs and persisted grant records. Malformed app-service
 * metadata fails closed with a Platform API exception and is ignored by discovery callers, while
 * unrelated manifest keys remain unaffected.
 *
 * <p>The extension schema deliberately separates provider declarations from consumer requests.
 * Provider aliases under {@code app.services.provides} describe what an installed app offers.
 * Request aliases under {@code app.services.requests} describe what another installed app expects
 * to ask for. Neither side creates authorization by itself; grants are persisted only through the
 * coordinator after a consumer request and host/operator approval.
 */
public final class AppServiceManifestParser {
  private static final Pattern APP_ID_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final Pattern TOKEN_PATTERN = Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final Pattern GRANT_ID_PATTERN = Pattern.compile("asg-[0-9a-f]{24,64}");
  private static final Pattern EVENT_ID_PATTERN = Pattern.compile("ase-[0-9a-f]{24,64}");
  private static final int MAX_APP_ID_LENGTH = 64;
  private static final int MAX_TOKEN_LENGTH = 80;
  private static final int MAX_ALIAS_COUNT = 16;
  private static final int MAX_MANIFEST_BYTES = 128 * 1024;
  private static final String PROVIDES_KEY = "app.services.provides";
  private static final String REQUESTS_KEY = "app.services.requests";
  private static final String FIELD_CONTEXTS = "contexts";
  private static final String FIELD_ERROR_PREFIX = "Field '";
  private static final String FIELD_SCOPES = "scopes";

  private AppServiceManifestParser() {}

  /**
   * Parses provider service declarations from one installed app manifest file.
   *
   * <p>The file is read with symlink checks and a fixed size limit. Returned descriptors use the
   * app id, display name, and version from the already parsed core manifest, not duplicated text
   * from the app-service extension keys.
   *
   * @param manifest parsed core AppHost manifest for the same installed file
   * @param manifestFile installed {@code cryptad-app.properties} path to parse
   * @return deterministic provider service descriptors declared by the manifest
   * @throws IOException when the manifest file cannot be read safely
   */
  public static List<AppServiceDescriptor> parseProvidedServices(
      AppManifest manifest, Path manifestFile) throws IOException {
    return parseProvidedServices(manifest, readManifestProperties(manifestFile));
  }

  /**
   * Parses consumer service request declarations from one installed app manifest file.
   *
   * <p>Request descriptors are operator-review metadata. They do not create grants, approve access,
   * or bypass the consumer manifest permission check. Grant creation still happens through the
   * Platform API request route.
   *
   * @param manifest parsed core AppHost manifest for the same installed file
   * @param manifestFile installed {@code cryptad-app.properties} path to parse
   * @return deterministic consumer request descriptors declared by the manifest
   * @throws IOException when the manifest file cannot be read safely
   */
  public static List<AppServiceRequestDescriptor> parseServiceRequests(
      AppManifest manifest, Path manifestFile) throws IOException {
    return parseServiceRequests(manifest, readManifestProperties(manifestFile));
  }

  /**
   * Parses provider declarations from properties text.
   *
   * <p>This helper is used by focused tests and release-certification fixtures. It applies the same
   * size limit, Java properties parsing, alias normalization, and descriptor validation as the
   * file-backed parser.
   *
   * @param manifest parsed core manifest metadata for the provider app
   * @param content properties text to parse
   * @return deterministic descriptors declared by the properties text
   * @throws IOException when the properties text cannot be parsed
   */
  public static List<AppServiceDescriptor> parseProvidedServicesContent(
      AppManifest manifest, String content) throws IOException {
    return parseProvidedServices(manifest, loadProperties(content));
  }

  /**
   * Parses consumer request declarations from properties text.
   *
   * <p>This helper mirrors {@link #parseServiceRequests(AppManifest, Path)} without filesystem
   * access. It is useful for validating staged bundles before installation and for deterministic
   * unit tests.
   *
   * @param manifest parsed core manifest metadata for the consumer app
   * @param content properties text to parse
   * @return deterministic request descriptors declared by the properties text
   * @throws IOException when the properties text cannot be parsed
   */
  public static List<AppServiceRequestDescriptor> parseServiceRequestsContent(
      AppManifest manifest, String content) throws IOException {
    return parseServiceRequests(manifest, loadProperties(content));
  }

  private static List<AppServiceDescriptor> parseProvidedServices(
      AppManifest manifest, Properties properties) {
    List<String> aliases = aliasList(properties.getProperty(PROVIDES_KEY), PROVIDES_KEY);
    ArrayList<AppServiceDescriptor> descriptors = new ArrayList<>();
    for (String alias : aliases) {
      String prefix = "app.service." + alias + ".";
      descriptors.add(
          new AppServiceDescriptor(
              manifest.appId(),
              manifest.appName(),
              manifest.appVersion(),
              requiredProperty(properties, prefix + "id"),
              requiredProperty(properties, prefix + "name"),
              requiredProperty(properties, prefix + "version"),
              requiredProperty(properties, prefix + "kind"),
              requiredProperty(properties, prefix + "adapter"),
              commaList(requiredProperty(properties, prefix + FIELD_SCOPES), prefix + FIELD_SCOPES),
              commaList(
                  optionalProperty(properties, prefix + FIELD_CONTEXTS), prefix + FIELD_CONTEXTS),
              optionalProperty(properties, prefix + "description"),
              optionalProperty(properties, prefix + "stability", "preview"),
              true));
    }
    return List.copyOf(descriptors);
  }

  private static List<AppServiceRequestDescriptor> parseServiceRequests(
      AppManifest manifest, Properties properties) {
    List<String> aliases = aliasList(properties.getProperty(REQUESTS_KEY), REQUESTS_KEY);
    ArrayList<AppServiceRequestDescriptor> descriptors = new ArrayList<>();
    for (String alias : aliases) {
      String prefix = "app.service-request." + alias + ".";
      descriptors.add(
          new AppServiceRequestDescriptor(
              manifest.appId(),
              manifest.appName(),
              manifest.appVersion(),
              requiredProperty(properties, prefix + "provider"),
              requiredProperty(properties, prefix + "service"),
              commaList(requiredProperty(properties, prefix + FIELD_SCOPES), prefix + FIELD_SCOPES),
              commaList(
                  optionalProperty(properties, prefix + FIELD_CONTEXTS), prefix + FIELD_CONTEXTS),
              requiredProperty(properties, prefix + "purpose")));
    }
    return List.copyOf(descriptors);
  }

  private static Properties readManifestProperties(Path manifestFile) throws IOException {
    Objects.requireNonNull(manifestFile, "manifestFile");
    if (Files.isSymbolicLink(manifestFile)
        || !Files.isRegularFile(manifestFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("app-service manifest is unavailable");
    }
    long size = Files.size(manifestFile);
    if (size > MAX_MANIFEST_BYTES) {
      throw new IOException("app-service manifest is too large");
    }
    return loadProperties(Files.readString(manifestFile, StandardCharsets.UTF_8));
  }

  private static Properties loadProperties(String content) throws IOException {
    String text = Objects.requireNonNull(content, "content");
    if (text.getBytes(StandardCharsets.UTF_8).length > MAX_MANIFEST_BYTES) {
      throw new IOException("app-service manifest is too large");
    }
    Properties properties = new Properties();
    properties.load(new StringReader(text));
    return properties;
  }

  private static List<String> aliasList(String raw, String propertyName) {
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    List<String> aliases = commaList(raw, propertyName);
    if (aliases.size() > MAX_ALIAS_COUNT) {
      throw invalid("Manifest property '" + propertyName + "' declares too many aliases.");
    }
    return aliases;
  }

  private static String requiredProperty(Properties properties, String key) {
    String value = properties.getProperty(key);
    if (value == null || value.isBlank()) {
      throw invalid("Manifest property '" + key + "' is required for app-service metadata.");
    }
    return value;
  }

  private static String optionalProperty(Properties properties, String key) {
    return optionalProperty(properties, key, null);
  }

  private static String optionalProperty(Properties properties, String key, String fallback) {
    String value = properties.getProperty(key);
    return value == null ? fallback : value;
  }

  /**
   * Parses a comma-separated token list with the app-service token normalizer.
   *
   * <p>Blank input means the field is absent and returns an empty list. Blank elements inside a
   * non-blank list are rejected so manifests cannot accidentally widen a service declaration by
   * carrying an ambiguous trailing comma. Duplicate values are removed by {@link #normalizeTokens}
   * while preserving first-seen order.
   *
   * @param raw raw comma-separated property or form value
   * @param fieldName field name used in validation errors
   * @return normalized immutable token list
   */
  static List<String> commaList(String raw, String fieldName) {
    if (raw == null || raw.isBlank()) {
      return List.of();
    }
    ArrayList<String> values = new ArrayList<>();
    for (String part : raw.split(",", -1)) {
      String trimmed = part.trim();
      if (trimmed.isEmpty()) {
        throw invalid(FIELD_ERROR_PREFIX + fieldName + "' must not contain empty values.");
      }
      values.add(normalizeToken(fieldName, trimmed));
    }
    return normalizeTokens(fieldName, values, MAX_ALIAS_COUNT);
  }

  /**
   * Normalizes and validates an installed app id.
   *
   * <p>App ids are lower-case route and manifest identifiers. The pattern intentionally matches the
   * AppHost app-id shape used by first-party manifests, including dots, underscores, and dashes
   * inside the id but not at either edge.
   *
   * @param value raw app id from a manifest, route segment, or stored grant
   * @return normalized lower-case app id
   */
  static String normalizeAppId(String value) {
    String normalized = requiredText("appId", value, MAX_APP_ID_LENGTH).toLowerCase(Locale.ROOT);
    if (!APP_ID_PATTERN.matcher(normalized).matches()) {
      throw invalid("App id is malformed.");
    }
    return normalized;
  }

  /**
   * Normalizes a public service or adapter id.
   *
   * <p>Service ids use the same bounded token grammar as scopes and contexts. The helper exists so
   * model constructors can make service-id intent explicit even though the grammar is shared.
   *
   * @param value raw service id or adapter id
   * @return normalized lower-case service id
   */
  static String normalizeServiceId(String value) {
    return normalizeToken("serviceId", value);
  }

  /**
   * Normalizes a persisted app-service grant id.
   *
   * <p>Grant ids are local metadata keys with the {@code asg-} prefix. They are never bearer
   * credentials, but strict validation prevents malformed route input from becoming a filesystem
   * name in the file-backed store.
   *
   * @param value raw grant id from a route or persisted record
   * @return normalized lower-case grant id
   */
  static String normalizeGrantId(String value) {
    String normalized = requiredText("grantId", value, 68).toLowerCase(Locale.ROOT);
    if (!GRANT_ID_PATTERN.matcher(normalized).matches()) {
      throw invalid("App-service grant id is malformed.");
    }
    return normalized;
  }

  /**
   * Normalizes a persisted app-service audit event id.
   *
   * <p>Event ids use the {@code ase-} prefix and are suitable as local durable record keys. They
   * identify audit rows only; they do not grant access and should not be treated as secrets.
   *
   * @param value raw audit event id from a generated event or persisted record
   * @return normalized lower-case audit event id
   */
  static String normalizeEventId(String value) {
    String normalized = requiredText("eventId", value, 68).toLowerCase(Locale.ROOT);
    if (!EVENT_ID_PATTERN.matcher(normalized).matches()) {
      throw invalid("App-service audit event id is malformed.");
    }
    return normalized;
  }

  /**
   * Normalizes a bounded token field used by service metadata.
   *
   * <p>The grammar accepts lower-case alphanumeric tokens with optional dot, underscore, or dash
   * separators. Inputs are trimmed and lower-cased before validation so manifests, route
   * parameters, and stored records compare consistently.
   *
   * @param fieldName field name used in validation errors
   * @param value raw token value
   * @return normalized lower-case token
   */
  static String normalizeToken(String fieldName, String value) {
    String normalized = requiredText(fieldName, value, MAX_TOKEN_LENGTH).toLowerCase(Locale.ROOT);
    if (!TOKEN_PATTERN.matcher(normalized).matches()) {
      throw invalid(FIELD_ERROR_PREFIX + fieldName + "' is malformed.");
    }
    return normalized;
  }

  /**
   * Normalizes a required token field with a caller-supplied length bound.
   *
   * <p>This is used for status-like and implementation-kind fields whose maximum length is tighter
   * than the general app-service token limit.
   *
   * @param fieldName field name used in validation errors
   * @param value raw token value
   * @param maxLength maximum supported character length after trimming
   * @return normalized lower-case token
   */
  static String requiredToken(String fieldName, String value, int maxLength) {
    String normalized = requiredText(fieldName, value, maxLength).toLowerCase(Locale.ROOT);
    if (!TOKEN_PATTERN.matcher(normalized).matches()) {
      throw invalid(FIELD_ERROR_PREFIX + fieldName + "' is malformed.");
    }
    return normalized;
  }

  /**
   * Normalizes an ordered token collection and removes duplicates.
   *
   * <p>Ordering is preserved because descriptor JSON, grant ids, and release evidence should be
   * deterministic. A maximum element count keeps manifest metadata and grant records bounded.
   *
   * @param fieldName field name used in validation errors
   * @param values raw or partially normalized token values
   * @param maxValues maximum number of values accepted before de-duplication
   * @return immutable normalized token list in first-seen order
   */
  static List<String> normalizeTokens(String fieldName, List<String> values, int maxValues) {
    Objects.requireNonNull(values, fieldName);
    if (values.isEmpty()) {
      return List.of();
    }
    if (values.size() > maxValues) {
      throw invalid(FIELD_ERROR_PREFIX + fieldName + "' contains too many values.");
    }
    Set<String> normalized = new LinkedHashSet<>();
    for (String value : values) {
      normalized.add(normalizeToken(fieldName, value));
    }
    return List.copyOf(normalized);
  }

  /**
   * Normalizes required operator-facing text.
   *
   * <p>The text is trimmed, bounded, and checked for unsupported control characters. The method
   * does not lower-case display text because app and service names should preserve their
   * human-readable casing.
   *
   * @param fieldName field name used in validation errors
   * @param value raw text value
   * @param maxLength maximum supported character length after trimming
   * @return trimmed text value
   */
  static String requiredText(String fieldName, String value, int maxLength) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw invalid(FIELD_ERROR_PREFIX + fieldName + "' is required.");
    }
    return optionalText(text, maxLength);
  }

  /**
   * Normalizes optional operator-facing text.
   *
   * <p>Blank values are treated as absent and returned as {@code null}. Non-blank values receive
   * the same bounds and control-character checks as required text so optional manifest fields are
   * safe to serialize directly in public JSON.
   *
   * @param value raw optional text
   * @param maxLength maximum supported character length after trimming
   * @return trimmed text, or {@code null} when absent
   */
  static String optionalText(String value, int maxLength) {
    if (value == null) {
      return null;
    }
    String text = value.trim();
    if (text.isEmpty()) {
      return null;
    }
    if (text.length() > maxLength) {
      throw invalid("Field value exceeds the supported length.");
    }
    for (int index = 0; index < text.length(); index++) {
      char ch = text.charAt(index);
      if (Character.isISOControl(ch) && ch != '\t') {
        throw invalid("Field value contains unsupported control characters.");
      }
    }
    return text;
  }

  private static PlatformApiException invalid(String message) {
    return new PlatformApiException(400, "invalid_app_service_manifest", message);
  }
}
