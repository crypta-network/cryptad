package network.crypta.platform.appcatalog;

import java.util.List;
import java.util.Objects;
import java.util.function.UnaryOperator;

/**
 * Provides the built-in first-party app catalog recommendation.
 *
 * <p>The provider reads only source and key-hint configuration from the runtime environment. It
 * does not embed catalog keys, public key bytes, private keys, or a placeholder network source.
 * When no source is configured, the returned first-party beta descriptor remains visible as "not
 * configured" so operators can understand what packaging or runtime configuration is missing.
 * Runtime code can therefore enable the Web Shell onboarding card without silently adding remote
 * catalog sources or implying that the catalog has already been trusted.
 *
 * <p>Configuration values follow the same system-property and environment-variable pattern used by
 * the app platform runtime:
 *
 * <pre>{@code
 * cryptad.firstPartyCatalog.enabled=true
 * cryptad.firstPartyCatalog.id=crypta-first-party-beta
 * cryptad.firstPartyCatalog.source=crypta:USK@.../cryptad-app-catalog.properties
 * cryptad.firstPartyCatalog.trustedCatalogKeyId=crypta-first-party-beta
 * cryptad.firstPartyCatalog.reviewerPolicyHint=first-party-review
 * }</pre>
 *
 * Environment variables with the matching {@code CRYPTAD_FIRST_PARTY_CATALOG_*} names are also
 * accepted. System properties take precedence over environment variables so tests, launchers, and
 * packaging wrappers can override inherited process environments deterministically.
 *
 * <p>The returned descriptors are immutable snapshots of configuration at the time of the call.
 * They do not watch system properties for later changes. Callers that need live reconfiguration
 * should call {@link #fromSystem()} again and then pass the resulting descriptors through their
 * normal API serialization or readiness checks.
 *
 * @see RecommendedAppCatalog
 * @see AppCatalogManager#addSource(String, String)
 */
public final class RecommendedAppCatalogs {
  /**
   * Stable id for the first-party public beta catalog recommendation.
   *
   * <p>This is the default catalog id the recommendation expects to see after signed-catalog
   * verification. Operators and packagers may override it for test or staging environments, but the
   * normal public beta path uses this value in API responses and Web Shell actions.
   */
  public static final String FIRST_PARTY_BETA_CATALOG_ID = "crypta-first-party-beta";

  /**
   * System property that enables or hides the first-party beta recommendation.
   *
   * <p>Set this property to {@code false}, {@code 0}, {@code no}, or {@code off} to suppress the
   * onboarding descriptor entirely. Any other non-blank value leaves the descriptor visible and is
   * treated the same as the default enabled state.
   */
  public static final String ENABLED_PROPERTY = "cryptad.firstPartyCatalog.enabled";

  /**
   * Environment variable that enables or hides the first-party beta recommendation.
   *
   * <p>This is the packaging-friendly companion to {@link #ENABLED_PROPERTY}. The system property
   * takes precedence when both are present, which lets tests and local launchers override inherited
   * service-manager environments.
   */
  public static final String ENABLED_ENV = "CRYPTAD_FIRST_PARTY_CATALOG_ENABLED";

  /**
   * System property that overrides the expected first-party catalog id.
   *
   * <p>The configured value is normalized by {@link RecommendedAppCatalog} before it appears in API
   * output or expected-id checks. Use this for controlled staging catalogs whose signed {@code
   * catalog.id} intentionally differs from the public beta default.
   */
  public static final String ID_PROPERTY = "cryptad.firstPartyCatalog.id";

  /**
   * Environment variable that overrides the expected first-party catalog id.
   *
   * <p>This is the deployment-environment form of {@link #ID_PROPERTY}. It should name only the
   * expected signed catalog id, not a source URI or signing key.
   */
  public static final String ID_ENV = "CRYPTAD_FIRST_PARTY_CATALOG_ID";

  /**
   * System property that supplies the first-party catalog source URI.
   *
   * <p>The value is parsed by {@link AppCatalogSource#parse(String)} and may use any catalog source
   * transport accepted for manual catalog add, including configured {@code crypta:} sources. A
   * blank or missing value keeps the descriptor visible but not ready to add.
   */
  public static final String SOURCE_PROPERTY = "cryptad.firstPartyCatalog.source";

  /**
   * Environment variable that supplies the first-party catalog source URI.
   *
   * <p>This is the packaging-friendly form of {@link #SOURCE_PROPERTY}. The source may contain
   * operator-sensitive details such as local paths or Crypta keys, so API layers must redact it
   * before returning recommendation summaries.
   */
  public static final String SOURCE_ENV = "CRYPTAD_FIRST_PARTY_CATALOG_SOURCE";

  /**
   * System property that names the trusted catalog signing key id hint.
   *
   * <p>The value is a stable key identifier used for readiness checks. It is not public key bytes
   * and is not sufficient to trust a catalog by itself; adding the recommendation still verifies
   * the signed catalog against the runtime trusted-key registry.
   */
  public static final String TRUSTED_CATALOG_KEY_ID_PROPERTY =
      "cryptad.firstPartyCatalog.trustedCatalogKeyId";

  /**
   * Environment variable that names the trusted catalog signing key id hint.
   *
   * <p>This is the deployment-environment companion to {@link #TRUSTED_CATALOG_KEY_ID_PROPERTY}. It
   * should carry only a short trusted-key id suitable for operator display and release evidence.
   */
  public static final String TRUSTED_CATALOG_KEY_ID_ENV =
      "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_CATALOG_KEY_ID";

  /**
   * Alternate system property accepted for shorter trusted-key hint configuration.
   *
   * <p>This alias exists for packaging environments that already use "trusted key" wording. The
   * canonical {@link #TRUSTED_CATALOG_KEY_ID_PROPERTY} is checked first and wins when both
   * properties are configured.
   */
  public static final String TRUSTED_KEY_ID_PROPERTY = "cryptad.firstPartyCatalog.trustedKeyId";

  /**
   * Alternate environment variable accepted for shorter trusted-key hint configuration.
   *
   * <p>This alias mirrors {@link #TRUSTED_KEY_ID_PROPERTY}. The canonical trusted-catalog-key
   * environment variable is checked first so deployments can migrate without changing behavior.
   */
  public static final String TRUSTED_KEY_ID_ENV = "CRYPTAD_FIRST_PARTY_CATALOG_TRUSTED_KEY_ID";

  /**
   * System property that supplies an advisory reviewer policy display hint.
   *
   * <p>The value is exposed as descriptive metadata only. It does not configure reviewer trust,
   * bypass review receipts, or relax install/update gates.
   */
  public static final String REVIEWER_POLICY_HINT_PROPERTY =
      "cryptad.firstPartyCatalog.reviewerPolicyHint";

  /**
   * Environment variable that supplies an advisory reviewer policy display hint.
   *
   * <p>This is the packaging-friendly form of {@link #REVIEWER_POLICY_HINT_PROPERTY}. Keep the
   * value short and stable because it may appear in operator API responses and certification
   * evidence.
   */
  public static final String REVIEWER_POLICY_HINT_ENV =
      "CRYPTAD_FIRST_PARTY_CATALOG_REVIEWER_POLICY_HINT";

  private static final String FIRST_PARTY_BETA_NAME = "Crypta First-Party Beta Catalog";
  private static final String FIRST_PARTY_BETA_DESCRIPTION =
      "First-party beta apps maintained by the Crypta project.";
  private static final String FIRST_PARTY_BETA_CHANNEL = "beta";

  private RecommendedAppCatalogs() {}

  /**
   * Returns recommendations built from the current JVM system properties and process environment.
   *
   * <p>The list contains the first-party beta descriptor by default. Set {@code
   * cryptad.firstPartyCatalog.enabled=false} or {@code CRYPTAD_FIRST_PARTY_CATALOG_ENABLED=false}
   * to hide it for a runtime that must not show first-party onboarding at all. The method performs
   * no network or filesystem access; it only reads process configuration and normalizes descriptor
   * fields. A malformed non-blank source or identifier fails fast with an {@link
   * AppCatalogException} so packaging mistakes are visible during startup, API tests, or release
   * certification.
   *
   * @return immutable list of recommended catalogs derived from current process configuration
   */
  public static List<RecommendedAppCatalog> fromSystem() {
    return fromConfig(System::getProperty, System::getenv);
  }

  static List<RecommendedAppCatalog> fromConfig(
      UnaryOperator<String> propertyReader, UnaryOperator<String> environmentReader) {
    UnaryOperator<String> checkedPropertyReader =
        Objects.requireNonNull(propertyReader, "propertyReader");
    UnaryOperator<String> checkedEnvironmentReader =
        Objects.requireNonNull(environmentReader, "environmentReader");
    String enabled =
        firstConfigured(
            checkedPropertyReader, checkedEnvironmentReader, ENABLED_PROPERTY, ENABLED_ENV);
    if (isDisabled(enabled)) {
      return List.of();
    }
    return List.of(
        RecommendedAppCatalog.fromRawSource(
            firstPartyCatalogId(checkedPropertyReader, checkedEnvironmentReader),
            FIRST_PARTY_BETA_NAME,
            FIRST_PARTY_BETA_DESCRIPTION,
            FIRST_PARTY_BETA_CHANNEL,
            firstConfigured(
                checkedPropertyReader, checkedEnvironmentReader, SOURCE_PROPERTY, SOURCE_ENV),
            trustedCatalogKeyId(checkedPropertyReader, checkedEnvironmentReader),
            firstConfigured(
                checkedPropertyReader,
                checkedEnvironmentReader,
                REVIEWER_POLICY_HINT_PROPERTY,
                REVIEWER_POLICY_HINT_ENV)));
  }

  private static String firstPartyCatalogId(
      UnaryOperator<String> propertyReader, UnaryOperator<String> environmentReader) {
    String configured = firstConfigured(propertyReader, environmentReader, ID_PROPERTY, ID_ENV);
    return configured == null ? FIRST_PARTY_BETA_CATALOG_ID : configured;
  }

  private static String firstConfigured(
      UnaryOperator<String> propertyReader,
      UnaryOperator<String> environmentReader,
      String propertyName,
      String environmentName) {
    String propertyValue = propertyReader.apply(propertyName);
    if (propertyValue != null && !propertyValue.isBlank()) {
      return propertyValue.trim();
    }
    String environmentValue = environmentReader.apply(environmentName);
    if (environmentValue != null && !environmentValue.isBlank()) {
      return environmentValue.trim();
    }
    return null;
  }

  private static String trustedCatalogKeyId(
      UnaryOperator<String> propertyReader, UnaryOperator<String> environmentReader) {
    String primary =
        firstConfigured(
            propertyReader,
            environmentReader,
            TRUSTED_CATALOG_KEY_ID_PROPERTY,
            TRUSTED_CATALOG_KEY_ID_ENV);
    return primary == null
        ? firstConfigured(
            propertyReader, environmentReader, TRUSTED_KEY_ID_PROPERTY, TRUSTED_KEY_ID_ENV)
        : primary;
  }

  private static boolean isDisabled(String value) {
    if (value == null) {
      return false;
    }
    return "false".equalsIgnoreCase(value)
        || "0".equals(value)
        || "no".equalsIgnoreCase(value)
        || "off".equalsIgnoreCase(value);
  }
}
