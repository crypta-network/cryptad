package network.crypta.platform.api.appcatalogs;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractVerifier;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.BackupRestoreSupport;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.DataSchemaPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.DeprecationPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.MigrationPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.SecurityPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.SupportLevel;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogProductionMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisory;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecision;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppReviewTransparencyEventKind;
import network.crypta.platform.appcatalog.AppReviewTransparencyLog;
import network.crypta.platform.appcatalog.AppReviewTransparencyQuery;
import network.crypta.platform.appcatalog.AppReviewTransparencyVerificationResult;
import network.crypta.platform.appcatalog.AppReviewTrustDecision;
import network.crypta.platform.appcatalog.RecommendedAppCatalog;
import network.crypta.platform.appcatalog.RecommendedAppCatalogs;
import network.crypta.platform.appcatalog.TrustedReviewerKeySummary;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appcatalog.TrustedReviewerKeysLoader;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appui.AppUiPaths;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Signed app-catalog endpoint family for Platform API v1.
 *
 * <p>The handler exposes catalog source management, catalog app listing, and install/update actions
 * while preserving the existing local staged-directory app routes. Catalog install and update first
 * obtain a verified temporary stage from {@link AppCatalogManager}, then call the same AppHost
 * methods used by the local app API. That keeps bundle verification and mutable directory semantics
 * centralized in AppHost.
 *
 * <p>Instances are transport-neutral. The router supplies decoded path and query values, and this
 * class returns JSON-compatible maps and lists that the shared Platform API JSON writer can encode.
 * Catalog failures stay expressed with stable machine-readable catalog codes, while AppHost
 * failures are translated to the same app lifecycle contracts used by local install and update
 * endpoints. The handler does not keep mutable request state; the shared {@link AppCatalogManager}
 * and {@link AppHost} own persistence, staging, and lifecycle decisions.
 */
public final class AppCatalogsApiHandler {
  private static final System.Logger LOG = System.getLogger(AppCatalogsApiHandler.class.getName());
  private static final PreparedPlanConsentVerifier NO_PREPARED_PLAN_CONSENT_VERIFIER = (_, _) -> {};

  private static final String APP_ALREADY_INSTALLED_PREFIX = "app already installed: ";
  private static final String APP_NOT_INSTALLED_PREFIX = "app is not installed: ";
  private static final String CANNOT_UPDATE_RUNNING_APP_PREFIX = "cannot update a running app: ";
  private static final String INSTALL_FAILED_MESSAGE = "Failed to install catalog app.";
  private static final String UPDATE_FAILED_MESSAGE = "Failed to update catalog app.";
  private static final String INVALID_APP_BUNDLE_ERROR_CODE = "invalid_app_bundle";
  private static final String APPHOST_BUNDLE_VALIDATION_MESSAGE =
      "Catalog app bundle failed AppHost validation.";
  private static final String VERSION_STATUS_NOT_INSTALLED = "not_installed";
  private static final String VERSION_STATUS_INSTALLED = "installed";
  private static final String VERSION_STATUS_CURRENT = "current";
  private static final String VERSION_STATUS_DIFFERENT = "different";
  private static final String VERSION_STATUS_UNKNOWN = "unknown";
  private static final String COMPATIBILITY_NOT_DECLARED = "not_declared";
  private static final String COMPATIBILITY_SATISFIED = "satisfied";
  private static final String COMPATIBILITY_NOT_SATISFIED = "not_satisfied";
  private static final String COMPATIBILITY_UNKNOWN = "unknown";
  private static final String SOURCE_FIELD = "source";
  private static final String SOURCE_TYPE_FIELD = "sourceType";
  private static final String SOURCE_KIND_FIELD = "sourceKind";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String APP_ID_FIELD = "appId";
  private static final String INSTALLED_FIELD = VERSION_STATUS_INSTALLED;
  private static final String INSTALLED_VERSION_FIELD = "installedVersion";
  private static final String LAST_ATTEMPT_AT_FIELD = "lastAttemptAt";
  private static final String LAST_SUCCESSFUL_REFRESH_AT_FIELD = "lastSuccessfulRefreshAt";
  private static final String LAST_FETCH_STATUS_FIELD = "lastFetchStatus";
  private static final String LAST_FETCH_ERROR_CODE_FIELD = "lastFetchErrorCode";
  private static final String LAST_FETCH_ERROR_MESSAGE_FIELD = "lastFetchErrorMessage";
  private static final String LAST_RESOLVED_URI_FIELD = "lastResolvedUri";
  private static final String FETCH_STATUS_SUCCESS = "success";
  private static final String FIELD_WARNINGS = "warnings";
  private static final String VAULT_GRANT_CLEANUP_WARNING =
      "Vault grant cleanup failed and requires operator review.";
  private static final String PARAM_REVIEW_ACKNOWLEDGED = "reviewAcknowledged";
  private static final String PARAM_SECURITY_ACKNOWLEDGED = "securityAcknowledged";
  private static final String REVIEW_TRUST_FIELD = "reviewTrust";
  private static final String SECURITY_DECISION_FIELD = "securityDecision";
  private static final String REVIEWER_KEY_ID_FIELD = "reviewerKeyId";
  private static final String STATUS_FIELD = "status";
  private static final String ADVISORY_FIELD = "advisory";
  private static final String ERROR_APP_REVIEW_MISSING = "app_review_missing";
  private static final String ERROR_APP_REVIEW_UNTRUSTED = "app_review_untrusted";
  private static final String ERROR_APP_REVIEW_REJECTED = "app_review_rejected";
  private static final String ERROR_APP_REVIEW_MISMATCH = "app_review_mismatch";
  private static final String ERROR_APP_REVIEW_EXPIRED = "app_review_expired";
  private static final String ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED =
      "app_security_acknowledgement_required";
  private static final String ERROR_APP_SECURITY_BLOCKED = "app_security_blocked";
  private static final String ERROR_APP_SECURITY_DENYLISTED = "app_security_denylisted";
  private static final String ERROR_RECOMMENDED_CATALOG_NOT_FOUND = "recommended_catalog_not_found";
  private static final String ERROR_RECOMMENDED_CATALOG_ALREADY_CONFIGURED =
      "recommended_catalog_already_configured";
  private static final String ERROR_RECOMMENDED_CATALOG_SOURCE_MISSING =
      "recommended_catalog_source_missing";
  private static final String ERROR_RECOMMENDED_CATALOG_TRUSTED_KEY_MISSING =
      "recommended_catalog_trusted_key_missing";
  private static final String ERROR_RECOMMENDED_CATALOG_INVALID_CONFIGURATION =
      "recommended_catalog_invalid_configuration";
  private static final String MISSING_SOURCE_CONFIGURATION = "source";
  private static final String MISSING_TRUSTED_CATALOG_KEY_CONFIGURATION = "trusted_catalog_key";

  private final AppCatalogManager catalogManager;
  private final AppHost appHost;
  private final Supplier<String> currentCryptaVersionSupplier;
  private final AppReviewPolicy reviewPolicy;
  private final ReviewerKeysProvider reviewerKeysProvider;
  private final AppVaultService appVaultService;
  private final Supplier<List<RecommendedAppCatalog>> recommendedCatalogsSupplier;

  /**
   * Creates a handler backed by a catalog manager and shared AppHost.
   *
   * <p>The supplied catalog manager is expected to use the same trusted-key policy as the AppHost
   * verification policy for PR-195. The handler performs no global lookup and does not cache
   * trusted keys itself, which lets runtime composition reload key material between requests when
   * configured to do so.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   */
  @SuppressWarnings("unused")
  public AppCatalogsApiHandler(AppCatalogManager catalogManager, AppHost appHost) {
    this(catalogManager, appHost, () -> null);
  }

  /**
   * Creates a handler backed by a catalog manager, AppHost, and node-version supplier.
   *
   * <p>The version supplier is used only for advisory compatibility metadata in read responses. It
   * is not involved in catalog signature verification, artifact staging, or install/update
   * decisions.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier) {
    this(catalogManager, appHost, currentCryptaVersionSupplier, null);
  }

  /**
   * Creates a handler backed by catalog services and optional vault lifecycle integration.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppVaultService appVaultService) {
    this(
        catalogManager,
        appHost,
        currentCryptaVersionSupplier,
        AppReviewPolicy.loadFromSystem(),
        trustedReviewerKeysFromSystem(),
        appVaultService);
  }

  /**
   * Creates a handler with explicit review policy and reviewer-key provider.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param reviewPolicy local review policy for install/update gates
   * @param reviewerKeysProvider provider for trusted reviewer keys
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider) {
    this(
        catalogManager,
        appHost,
        currentCryptaVersionSupplier,
        reviewPolicy,
        reviewerKeysProvider,
        null);
  }

  /**
   * Creates a handler with explicit review policy, reviewer-key provider, and optional vault.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param reviewPolicy local review policy for install/update gates
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService) {
    this(
        catalogManager,
        appHost,
        currentCryptaVersionSupplier,
        reviewPolicy,
        reviewerKeysProvider,
        appVaultService,
        RecommendedAppCatalogs::fromSystem);
  }

  /**
   * Creates a handler with explicit recommendation and review collaborators.
   *
   * <p>Tests and controlled embeddings use this constructor to provide deterministic recommended
   * catalog descriptors without relying on process-wide system properties. Runtime composition
   * normally uses {@link RecommendedAppCatalogs#fromSystem()} through the shorter constructors.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param reviewPolicy local review policy for install/update gates
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   * @param recommendedCatalogsSupplier supplier for configured recommended catalog descriptors
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService,
      Supplier<List<RecommendedAppCatalog>> recommendedCatalogsSupplier) {
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.currentCryptaVersionSupplier =
        Objects.requireNonNull(currentCryptaVersionSupplier, "currentCryptaVersionSupplier");
    this.reviewPolicy = Objects.requireNonNull(reviewPolicy, "reviewPolicy");
    this.reviewerKeysProvider =
        Objects.requireNonNull(reviewerKeysProvider, "reviewerKeysProvider");
    this.appVaultService = appVaultService;
    this.recommendedCatalogsSupplier =
        Objects.requireNonNull(recommendedCatalogsSupplier, "recommendedCatalogsSupplier");
  }

  private static ReviewerKeysProvider trustedReviewerKeysFromSystem() {
    return TrustedReviewerKeysLoader::loadFromSystem;
  }

  /** Supplies trusted reviewer keys for independent review-receipt checks. */
  @FunctionalInterface
  public interface ReviewerKeysProvider {
    /**
     * Returns local trusted reviewer keys.
     *
     * @return trusted reviewer registry
     * @throws IOException if configured key material cannot be read
     */
    TrustedReviewerKeys trustedReviewerKeys() throws IOException;
  }

  /** Verifies consent against a prepared catalog plan entry before install or update commits. */
  @FunctionalInterface
  public interface PreparedPlanConsentVerifier {
    /**
     * Verifies that the prepared plan entry still matches the approved operator consent snapshot.
     *
     * @param catalogId catalog identifier attached to the prepared plan
     * @param entry prepared catalog entry
     */
    void verify(String catalogId, AppCatalogEntry entry);
  }

  /**
   * Lists configured catalog sources.
   *
   * <p>Every stored catalog is re-read through the manager, which re-verifies the persisted catalog
   * sidecars before exposing metadata. A corrupt or no-longer-trusted catalog therefore returns a
   * catalog error instead of stale cached data.
   *
   * @return JSON-compatible catalog source summaries in manager-defined order
   */
  public List<Map<String, Object>> listCatalogs() {
    try {
      return catalogManager.listCatalogs().stream().map(this::summarizeCatalog).toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list app catalogs.");
    }
  }

  /**
   * Lists operator-visible recommended catalog descriptors.
   *
   * <p>This read path does not fetch remote catalog bytes and does not mutate configured sources.
   * It combines the recommendation provider with the current configured-catalog ids and trusted-key
   * hints so the Web Shell can show whether the first-party beta onboarding card is ready to add,
   * already configured, or missing runtime configuration.
   *
   * @return JSON-compatible recommended catalog summaries
   */
  public List<Map<String, Object>> listRecommendedCatalogs() {
    List<RecommendedAppCatalog> recommendedCatalogs = recommendedCatalogs();
    try {
      Set<String> configuredIds = configuredCatalogIds();
      return recommendedCatalogs.stream()
          .map(recommended -> summarizeRecommendedCatalog(recommended, configuredIds))
          .toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list recommended app catalogs.");
    }
  }

  /**
   * Adds one recommended catalog through the verified signed-catalog path.
   *
   * <p>The method never installs apps. It checks that the recommendation exists, has a configured
   * source, has its trusted catalog key hint present in the current trusted-key registry, and is
   * not already configured. The final mutation delegates to {@link
   * AppCatalogManager#addSource(String, String)}, which fetches and verifies the signed catalog
   * before persisting it and enforces that the authenticated catalog id matches the selected
   * recommendation.
   *
   * @param catalogId recommended catalog id from the request path
   * @return JSON-compatible summary for the newly stored and verified catalog
   */
  public Map<String, Object> addRecommended(String catalogId) {
    RecommendedAppCatalog recommended = recommendedCatalog(catalogId);
    if (recommended.sourceDisplayUri().isEmpty()) {
      throw new PlatformApiException(
          400,
          ERROR_RECOMMENDED_CATALOG_SOURCE_MISSING,
          "Recommended catalog source is not configured.");
    }
    try {
      if (configuredCatalogIds().contains(recommended.catalogId())) {
        throw new PlatformApiException(
            409,
            ERROR_RECOMMENDED_CATALOG_ALREADY_CONFIGURED,
            "Recommended catalog is already configured.");
      }
      if (!trustedCatalogKeyConfigured(recommended)) {
        throw new PlatformApiException(
            400,
            ERROR_RECOMMENDED_CATALOG_TRUSTED_KEY_MISSING,
            "Recommended catalog trusted key is not configured.");
      }
      return summarizeCatalog(
          catalogManager.addSource(
              recommended.sourceDisplayUri().orElseThrow(), recommended.catalogId()));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to add recommended app catalog.");
    }
  }

  /**
   * Adds a signed catalog source and returns the verified catalog summary.
   *
   * <p>The {@code source} parameter may name a local file, a {@code file:} URI, an HTTPS URI, or a
   * loopback HTTP URI accepted by the catalog source policy. Adding is intentionally eager: the
   * source is fetched, its signature is checked, the catalog is parsed, and only then is the source
   * persisted.
   *
   * @param queryParameters decoded request query or form parameters containing {@code source}
   * @return JSON-compatible summary for the newly stored and verified catalog
   */
  public Map<String, Object> add(Map<String, List<String>> queryParameters) {
    String source = PlatformApiParameters.requireString(queryParameters, SOURCE_FIELD);
    try {
      return summarizeCatalog(catalogManager.addSource(source));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to add app catalog.");
    }
  }

  private List<RecommendedAppCatalog> recommendedCatalogs() {
    try {
      return List.copyOf(recommendedCatalogsSupplier.get());
    } catch (AppCatalogException _) {
      throw new PlatformApiException(
          400,
          ERROR_RECOMMENDED_CATALOG_INVALID_CONFIGURATION,
          "Recommended catalog configuration is invalid.");
    }
  }

  private RecommendedAppCatalog recommendedCatalog(String catalogId) {
    String normalizedCatalogId;
    try {
      normalizedCatalogId =
          network.crypta.platform.appcatalog.AppCatalog.normalizeCatalogId(catalogId);
    } catch (AppCatalogException _) {
      throw recommendedCatalogNotFound();
    }
    return recommendedCatalogs().stream()
        .filter(recommended -> recommended.catalogId().equals(normalizedCatalogId))
        .findFirst()
        .orElseThrow(AppCatalogsApiHandler::recommendedCatalogNotFound);
  }

  private static PlatformApiException recommendedCatalogNotFound() {
    return new PlatformApiException(
        404, ERROR_RECOMMENDED_CATALOG_NOT_FOUND, "Recommended catalog not found.");
  }

  private Set<String> configuredCatalogIds() throws IOException {
    LinkedHashSet<String> configuredIds = new LinkedHashSet<>();
    for (AppCatalogSourceSnapshot snapshot : catalogManager.listCatalogs()) {
      configuredIds.add(snapshot.catalogId());
    }
    return Set.copyOf(configuredIds);
  }

  private Map<String, Object> summarizeRecommendedCatalog(
      RecommendedAppCatalog recommended, Set<String> configuredCatalogIds) {
    boolean configured = configuredCatalogIds.contains(recommended.catalogId());
    boolean trustedCatalogKeyConfigured = trustedCatalogKeyConfigured(recommended);
    List<String> missingConfiguration =
        missingRecommendedCatalogConfiguration(recommended, trustedCatalogKeyConfigured);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put(CATALOG_ID_FIELD, recommended.catalogId());
    json.put("name", recommended.name());
    json.put("description", recommended.description());
    json.put("channel", recommended.channel());
    json.put("defaultEntryChannel", "stable");
    json.put("availableEntryChannels", List.of("stable", "beta", "nightly", "deprecated"));
    json.put(SOURCE_KIND_FIELD, recommended.sourceKind().orElse(null));
    json.put(SOURCE_FIELD, redactedRecommendedSource(recommended));
    json.put("sourceConfigured", recommended.configured());
    json.put("configured", configured);
    json.put("trustedCatalogKeyId", recommended.trustedCatalogKeyId().orElse(null));
    json.put("trustedCatalogKeyConfigured", trustedCatalogKeyConfigured);
    json.put("reviewerPolicyHint", recommended.reviewerPolicyHint().orElse(null));
    json.put("canAdd", !configured && missingConfiguration.isEmpty());
    json.put("missingConfiguration", missingConfiguration);
    json.put(FIELD_WARNINGS, recommendedWarnings(configured, missingConfiguration));
    return json;
  }

  private boolean trustedCatalogKeyConfigured(RecommendedAppCatalog recommended) {
    Optional<String> trustedCatalogKeyId = recommended.trustedCatalogKeyId();
    if (trustedCatalogKeyId.isEmpty()) {
      return false;
    }
    try {
      return catalogManager.hasTrustedCatalogKey(trustedCatalogKeyId.orElseThrow());
    } catch (AppCatalogException | IOException _) {
      return false;
    }
  }

  private static List<String> missingRecommendedCatalogConfiguration(
      RecommendedAppCatalog recommended, boolean trustedCatalogKeyConfigured) {
    ArrayList<String> missing = new ArrayList<>(2);
    if (recommended.sourceDisplayUri().isEmpty()) {
      missing.add(MISSING_SOURCE_CONFIGURATION);
    }
    if (!trustedCatalogKeyConfigured) {
      missing.add(MISSING_TRUSTED_CATALOG_KEY_CONFIGURATION);
    }
    return List.copyOf(missing);
  }

  private static List<String> recommendedWarnings(boolean configured, List<String> missing) {
    ArrayList<String> warnings = new ArrayList<>();
    if (configured) {
      warnings.add(ERROR_RECOMMENDED_CATALOG_ALREADY_CONFIGURED);
    }
    for (String missingItem : missing) {
      warnings.add("missing_" + missingItem);
    }
    return List.copyOf(warnings);
  }

  private static String redactedRecommendedSource(RecommendedAppCatalog recommended) {
    Optional<String> source = recommended.sourceDisplayUri();
    if (source.isEmpty()) {
      return null;
    }
    Optional<String> sourceKind = recommended.sourceKind();
    if (sourceKind.isPresent() && "crypta".equals(sourceKind.orElseThrow())) {
      return "crypta:<configured>";
    }
    if (sourceKind.isPresent() && "file".equals(sourceKind.orElseThrow())) {
      return "file:<configured>";
    }
    URI uri = URI.create(source.orElseThrow());
    if (uri.getQuery() == null) {
      return uri.toString();
    }
    try {
      return new URI(
              uri.getScheme(),
              null,
              uri.getHost(),
              uri.getPort(),
              uri.getPath(),
              "<redacted>",
              null)
          .toString();
    } catch (java.net.URISyntaxException _) {
      return uri.getScheme() + "://<configured>";
    }
  }

  /**
   * Removes one configured catalog source.
   *
   * <p>Removal deletes the locally configured source record and cached catalog sidecars. It does
   * not uninstall apps that were previously installed from that catalog, because installed app
   * lifecycle remains owned by the app endpoints.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible removal summary containing the requested id and removal flag
   */
  public Map<String, Object> remove(String catalogId) {
    try {
      catalogManager.remove(catalogId);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put("removed", true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to remove app catalog.");
    }
  }

  /**
   * Refreshes one configured catalog source.
   *
   * <p>Refresh reuses the stored source URI, fetches fresh catalog sidecars, verifies the
   * signature, and rejects the result if the authenticated catalog id no longer matches the
   * configured id. A failed refresh leaves the previous stored sidecars in place.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible summary for the refreshed catalog
   */
  public Map<String, Object> refresh(String catalogId) {
    try {
      return summarizeCatalog(catalogManager.refresh(catalogId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to refresh app catalog.");
    }
  }

  /**
   * Lists apps in one catalog.
   *
   * <p>The response preserves the catalog-declared app order and adds local AppHost state for each
   * entry. Bundle URI, digest, and size metadata remain visible so operators can inspect what a
   * catalog would download before installing or updating.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible app entries enriched with local installed/running state
   */
  public List<Map<String, Object>> listApps(String catalogId) {
    try {
      return catalogManager.listApps(catalogId).stream()
          .map(entry -> summarizeEntry(catalogId, entry))
          .toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list catalog apps.");
    }
  }

  /**
   * Describes one app in a catalog.
   *
   * <p>The app id is resolved through the verified catalog, not directly through AppHost. That
   * keeps {@code app_not_found} distinct from an installed-app lookup failure and lets callers
   * inspect a catalog entry even when the app is not installed locally.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return JSON-compatible app entry enriched with local installed/running state
   */
  public Map<String, Object> getApp(String catalogId, String appId) {
    try {
      return summarizeEntry(catalogId, catalogManager.getApp(catalogId, appId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app.");
    }
  }

  /**
   * Returns catalog app metadata for update consent without blocking corrupt-install repair.
   *
   * <p>The catalog update mutation intentionally allows AppHost to repair an installed app whose
   * manifest is unreadable by applying a valid signed catalog bundle. Consent preview and
   * validation must preserve that repair path, so this summary is conservative when the installed
   * manifest cannot be read: it avoids exposing the raw failure, treats the app as locally present
   * with an unknown version, and reports catalog permissions as added.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return JSON-compatible app entry suitable for catalog update consent
   */
  public Map<String, Object> getAppForCatalogUpdateConsent(String catalogId, String appId) {
    try {
      return summarizeEntry(catalogId, catalogManager.getApp(catalogId, appId), true);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app.");
    }
  }

  /**
   * Summarizes a prepared catalog plan entry for a final consent digest check.
   *
   * <p>The installation/update routes call this after the catalog manager has downloaded and
   * verified the candidate bundle. The resulting summary uses the same redacted, path-free shape as
   * catalog preview responses so the consent layer can reject stale approvals when prepared
   * metadata no longer matches the operator-reviewed snapshot.
   *
   * @param catalogId catalog identifier attached to the prepared plan
   * @param entry prepared catalog entry
   * @param tolerateInstalledReadFailure whether corrupt installed manifests should remain
   *     repairable through update
   * @return path-free catalog entry summary suitable for consent digesting
   */
  public Map<String, Object> summarizePreparedPlanForConsent(
      String catalogId, AppCatalogEntry entry, boolean tolerateInstalledReadFailure) {
    return summarizeEntry(catalogId, entry, tolerateInstalledReadFailure);
  }

  /**
   * Returns redacted app-review governance state.
   *
   * @return review policy, reviewer registry, and transparency-log status
   */
  public Map<String, Object> governance() {
    TrustedReviewerKeys keys = trustedReviewerKeysOrEmpty();
    AppReviewTransparencyLog log = reviewTransparencyLog();
    AppReviewTransparencyVerificationResult verification = log.verify();
    LinkedHashMap<String, Object> transparency = LinkedHashMap.newLinkedHashMap(4);
    transparency.put("configured", log.configured());
    transparency.put("recordCount", log.recordCount());
    transparency.put("latestRecordHash", log.latestRecordHash());
    transparency.put("verified", verification.verified());
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("reviewPolicyMode", reviewPolicy.mode().jsonValue());
    json.put("trustedReviewerRegistry", keys.summary().toJsonValue());
    json.put("transparencyLog", transparency);
    return json;
  }

  /**
   * Returns redacted trusted-reviewer key summaries.
   *
   * @return reviewer-key list and registry summary
   */
  public Map<String, Object> reviewerKeys() {
    TrustedReviewerKeys keys = trustedReviewerKeysOrEmpty();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(
        "keys", keys.summaries().stream().map(TrustedReviewerKeySummary::toJsonValue).toList());
    json.put("registry", keys.summary().toJsonValue());
    return json;
  }

  /**
   * Returns one bounded transparency-log page.
   *
   * @param queryParameters decoded query parameters
   * @return redacted transparency page
   */
  public Map<String, Object> transparencyLog(Map<String, List<String>> queryParameters) {
    return reviewTransparencyLog().page(transparencyQuery(queryParameters)).toJsonValue();
  }

  /**
   * Verifies the local transparency-log hash chain.
   *
   * @return redacted verification result
   */
  public Map<String, Object> verifyTransparencyLog() {
    return reviewTransparencyLog().verify().toJsonValue();
  }

  /**
   * Returns review history for one catalog app.
   *
   * @param catalogId catalog identifier
   * @param appId app identifier
   * @return current review metadata, local trust decision, reviewer summary, and log records
   */
  public Map<String, Object> reviewHistory(String catalogId, String appId) {
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      AppReviewTrustDecision decision = reviewTrust(entry);
      AppReviewTransparencyQuery query =
          new AppReviewTransparencyQuery(
              AppReviewTransparencyQuery.DEFAULT_LIMIT, null, entry.appId(), catalogId, null, null);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(APP_ID_FIELD, entry.appId());
      json.put("catalogVersion", entry.version());
      json.put(INSTALLED_VERSION_FIELD, installedVersion(entry.appId()));
      json.put("review", summarizeReview(entry.review()));
      json.put(REVIEW_TRUST_FIELD, decision.toJsonValue());
      json.put("reviewerKey", reviewerKeySummary(decision.reviewerKeyId()));
      json.put("transparencyLog", reviewTransparencyLog().page(query).toJsonValue());
      json.put("trustDelta", reviewTrustDelta(entry, decision));
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app review history.");
    }
  }

  /**
   * Installs one catalog app through AppHost.
   *
   * <p>The method first confirms that the catalog entry exists and that the app is not already
   * installed. It then asks the manager to download, digest-check, extract, and verify the signed
   * bundle before delegating the final copy into the managed app tree to AppHost. Scratch cleanup
   * runs after the mutation and is logged if it fails so cleanup trouble does not mask a committed
   * installation.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> install(String catalogId, String appId) {
    return install(catalogId, appId, Map.of());
  }

  /**
   * Installs one catalog app through AppHost with optional review acknowledgement.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @return installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> install(
      String catalogId, String appId, Map<String, List<String>> queryParameters) {
    return install(catalogId, appId, queryParameters, NO_PREPARED_PLAN_CONSENT_VERIFIER);
  }

  /**
   * Validates the fast catalog-install state preconditions without preparing or installing a
   * bundle.
   *
   * <p>Consent-gated transport routes call this before asking for approval so impossible
   * installations retain the same conflict and catalog lookup errors as the mutation path. The full
   * {@link #install(String, String, Map, PreparedPlanConsentVerifier)} method rechecks these
   * conditions before it mutates state.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   */
  public void requireInstallPreconditions(String catalogId, String appId) {
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      if (appHost.describe(entry.appId()).isPresent()) {
        throw conflict(APP_ALREADY_INSTALLED_PREFIX + entry.appId());
      }
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    }
  }

  /**
   * Installs one catalog app with optional acknowledgement and prepared-plan consent verification.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @param preparedPlanConsentVerifier verifier invoked after bundle preparation and before install
   * @return installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> install(
      String catalogId,
      String appId,
      Map<String, List<String>> queryParameters,
      PreparedPlanConsentVerifier preparedPlanConsentVerifier) {
    Objects.requireNonNull(preparedPlanConsentVerifier, "preparedPlanConsentVerifier");
    String normalizedAppId;
    AppReviewTrustDecision initialReviewTrust;
    AppCatalogSecurityDecision initialSecurityDecision;
    boolean reviewAcknowledged = reviewAcknowledged(queryParameters);
    boolean securityAcknowledged = securityAcknowledged(queryParameters);
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
      if (appHost.describe(normalizedAppId).isPresent()) {
        throw conflict(APP_ALREADY_INSTALLED_PREFIX + normalizedAppId);
      }
      initialSecurityDecision = targetSecurityDecision(catalogId, entry);
      requireSecurityGate(initialSecurityDecision, securityAcknowledged, true);
      initialReviewTrust = reviewTrust(entry);
      recordReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
          catalogId,
          entry,
          initialReviewTrust,
          reviewAcknowledged,
          "catalog_entry");
      requireReviewGate(initialReviewTrust, reviewAcknowledged, true);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    }
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
      preparedPlanConsentVerifier.verify(plan.catalogId(), plan.entry());
      AppCatalogSecurityDecision preparedSecurityDecision =
          targetSecurityDecision(plan.catalogId(), plan.entry());
      requireSecurityGate(
          preparedSecurityDecision,
          securityAcknowledgementStillApplies(
              initialSecurityDecision, preparedSecurityDecision, securityAcknowledged),
          true);
      AppReviewTrustDecision preparedReviewTrust = reviewTrust(plan.entry());
      recordReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
          catalogId,
          plan.entry(),
          preparedReviewTrust,
          reviewAcknowledged,
          "prepared_plan");
      requireReviewGate(
          preparedReviewTrust,
          reviewAcknowledgementStillApplies(
              initialReviewTrust, preparedReviewTrust, reviewAcknowledged),
          true);
      InstalledAppSnapshot installed = appHost.installFromDirectory(plan.stagedBundleDirectory());
      return summarizeInstalledApp(installed.manifest());
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (AppHostException exception) {
      throw installFailure(exception);
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    } finally {
      cleanUpPlan(plan);
    }
  }

  /**
   * Updates one installed app from a catalog entry through AppHost.
   *
   * <p>The update path refuses running apps before staging remote data and fails fast when the app
   * is clearly not installed. If the installed manifest is unreadable, the method still lets
   * AppHost attempt the update so a valid catalog bundle can repair a damaged installation. The
   * staged bundle follows the same catalog digest, extraction, and signed-bundle verification path
   * as install.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return updated installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> update(String catalogId, String appId) {
    return update(catalogId, appId, Map.of());
  }

  /**
   * Updates one installed app from a catalog entry with optional review acknowledgement.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @return updated installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> update(
      String catalogId, String appId, Map<String, List<String>> queryParameters) {
    return update(catalogId, appId, queryParameters, NO_PREPARED_PLAN_CONSENT_VERIFIER);
  }

  /**
   * Validates the fast catalog-update state preconditions without preparing or updating a bundle.
   *
   * <p>Consent-gated transport routes call this before asking for approval so impossible updates
   * retain the same running-app, missing-app, and catalog lookup errors as the mutation path. The
   * full {@link #update(String, String, Map, PreparedPlanConsentVerifier)} method rechecks these
   * conditions before it mutates state.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   */
  public void requireUpdatePreconditions(String catalogId, String appId) {
    String normalizedAppId;
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    }
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + normalizedAppId);
    }
    try {
      if (appHost.describe(normalizedAppId).isEmpty()) {
        throw new PlatformApiException(404, "app_not_found", "App not found.");
      }
    } catch (IOException _) {
      // Allow AppHost to repair installs whose manifest is unreadable.
    }
  }

  /**
   * Updates one installed app with optional acknowledgement and prepared-plan consent verification.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @param preparedPlanConsentVerifier verifier invoked after bundle preparation and before update
   * @return updated installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> update(
      String catalogId,
      String appId,
      Map<String, List<String>> queryParameters,
      PreparedPlanConsentVerifier preparedPlanConsentVerifier) {
    Objects.requireNonNull(preparedPlanConsentVerifier, "preparedPlanConsentVerifier");
    String normalizedAppId;
    AppCatalogEntry entry;
    try {
      entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    }
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + normalizedAppId);
    }
    try {
      if (appHost.describe(normalizedAppId).isEmpty()) {
        throw new PlatformApiException(404, "app_not_found", "App not found.");
      }
    } catch (IOException _) {
      // Allow AppHost to repair installs whose manifest is unreadable.
    }
    AppReviewTrustDecision initialReviewTrust = reviewTrust(entry);
    boolean reviewAcknowledged = reviewAcknowledged(queryParameters);
    AppCatalogSecurityDecision initialSecurityDecision = targetSecurityDecision(catalogId, entry);
    boolean securityAcknowledged = securityAcknowledged(queryParameters);
    requireSecurityGate(initialSecurityDecision, securityAcknowledged, false);
    recordReviewGate(
        AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE,
        catalogId,
        entry,
        initialReviewTrust,
        reviewAcknowledged,
        "catalog_entry");
    requireReviewGate(initialReviewTrust, reviewAcknowledged, false);
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
      preparedPlanConsentVerifier.verify(plan.catalogId(), plan.entry());
      AppCatalogSecurityDecision preparedSecurityDecision =
          targetSecurityDecision(plan.catalogId(), plan.entry());
      requireSecurityGate(
          preparedSecurityDecision,
          securityAcknowledgementStillApplies(
              initialSecurityDecision, preparedSecurityDecision, securityAcknowledged),
          false);
      AppReviewTrustDecision preparedReviewTrust = reviewTrust(plan.entry());
      recordReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE,
          catalogId,
          plan.entry(),
          preparedReviewTrust,
          reviewAcknowledged,
          "prepared_plan");
      requireReviewGate(
          preparedReviewTrust,
          reviewAcknowledgementStillApplies(
              initialReviewTrust, preparedReviewTrust, reviewAcknowledged),
          false);
      InstalledAppSnapshot updated =
          appHost.updateFromDirectory(normalizedAppId, plan.stagedBundleDirectory());
      boolean vaultCleanupSucceeded = disableVaultGrantsRemovedByUpdate(updated);
      Map<String, Object> summary = summarizeInstalledApp(updated.manifest());
      if (!vaultCleanupSucceeded) {
        summary.put(FIELD_WARNINGS, List.of(VAULT_GRANT_CLEANUP_WARNING));
      }
      return summary;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (AppHostException exception) {
      throw updateFailure(normalizedAppId, exception);
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    } finally {
      cleanUpPlan(plan);
    }
  }

  private static void cleanUpPlan(AppCatalogInstallPlan plan) {
    if (plan == null) {
      return;
    }
    try {
      plan.close();
    } catch (IOException exception) {
      LOG.log(
          System.Logger.Level.WARNING, "Failed to clean catalog app scratch directory", exception);
    }
  }

  private boolean disableVaultGrantsRemovedByUpdate(InstalledAppSnapshot updated) {
    if (appVaultService == null) {
      return true;
    }
    try {
      appVaultService.disableGrantsForRemovedVaultPermissions(
          updated.appId(), new LinkedHashSet<>(updated.manifest().permissions()));
      return true;
    } catch (AppVaultException exception) {
      LOG.log(
          System.Logger.Level.WARNING,
          "Catalog update applied but vault grant cleanup failed: " + exception.errorCode());
      return false;
    }
  }

  private AppReviewTrustDecision reviewTrust(AppCatalogEntry entry) {
    return AppReviewReceiptVerifier.evaluate(
        entry, trustedReviewerKeysOrEmpty(), reviewPolicy, Instant.now());
  }

  private AppCatalogSecurityDecision securityDecision(String catalogId, AppCatalogEntry entry) {
    try {
      AppCatalogSecurityDecision decision =
          catalogManager.securityDecision(catalogId, entry.appId());
      return decision == null ? AppCatalogSecurityDecision.OK : decision;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app security policy.");
    }
  }

  private AppCatalogSecurityDecision targetSecurityDecision(
      String catalogId, AppCatalogEntry entry) {
    return AppCatalogSecurityDecision.combine(
        List.of(
            securityDecision(catalogId, entry),
            installedSecurityDecision(entry.appId(), entry.version())));
  }

  private AppCatalogSecurityDecision installedSecurityDecision(String appId, String version) {
    if (version == null || version.isBlank()) {
      return AppCatalogSecurityDecision.OK;
    }
    try {
      AppCatalogSecurityDecision decision =
          catalogManager.installedSecurityDecision(appId, version);
      return decision == null ? AppCatalogSecurityDecision.OK : decision;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read installed app security policy.");
    }
  }

  private void recordReviewGate(
      AppReviewTransparencyEventKind kind,
      String catalogId,
      AppCatalogEntry entry,
      AppReviewTrustDecision decision,
      boolean reviewAcknowledged,
      String phase) {
    reviewTransparencyLog()
        .recordCatalogDecision(
            kind,
            catalogId,
            entry,
            decision,
            List.of("phase=" + phase, "reviewAcknowledged=" + reviewAcknowledged));
  }

  private TrustedReviewerKeys trustedReviewerKeysOrEmpty() {
    try {
      return reviewerKeysProvider.trustedReviewerKeys();
    } catch (AppCatalogException | IOException _) {
      return TrustedReviewerKeys.empty();
    }
  }

  private AppReviewTransparencyLog reviewTransparencyLog() {
    AppReviewTransparencyLog log = catalogManager.reviewTransparencyLog();
    return log == null ? AppReviewTransparencyLog.disabled() : log;
  }

  private Map<String, Object> reviewerKeySummary(String reviewerKeyId) {
    if (reviewerKeyId == null || reviewerKeyId.isBlank()) {
      return Map.of();
    }
    return trustedReviewerKeysOrEmpty()
        .find(reviewerKeyId)
        .map(key -> TrustedReviewerKeySummary.from(key).toJsonValue())
        .orElseGet(Map::of);
  }

  private String installedVersion(String appId) {
    InstalledAppSnapshot installed = installed(appId);
    return installed == null ? null : installed.manifest().appVersion();
  }

  private Map<String, Object> reviewTrustDelta(
      AppCatalogEntry entry, AppReviewTrustDecision decision) {
    String installedVersion = installedVersion(entry.appId());
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put(INSTALLED_VERSION_FIELD, installedVersion);
    json.put("catalogVersion", entry.version());
    json.put(
        "versionChanged", installedVersion != null && !installedVersion.equals(entry.version()));
    json.put(REVIEWER_KEY_ID_FIELD, decision.reviewerKeyId());
    json.put("reviewerKeyStatus", decision.reviewerKeyStatus());
    json.put("trustStatus", decision.status().jsonValue());
    json.put("policyId", decision.policyId());
    json.put("policyVersion", decision.policyVersion());
    return json;
  }

  private static AppReviewTransparencyQuery transparencyQuery(
      Map<String, List<String>> queryParameters) {
    int limit = parseLimit(PlatformApiParameters.readOptionalString(queryParameters, "limit"));
    String cursor = PlatformApiParameters.readOptionalString(queryParameters, "cursor");
    String appId = PlatformApiParameters.readOptionalString(queryParameters, APP_ID_FIELD);
    String catalogId = PlatformApiParameters.readOptionalString(queryParameters, CATALOG_ID_FIELD);
    String reviewerKeyId =
        PlatformApiParameters.readOptionalString(queryParameters, REVIEWER_KEY_ID_FIELD);
    String kindText = PlatformApiParameters.readOptionalString(queryParameters, "kind");
    AppReviewTransparencyEventKind kind = null;
    if (kindText != null && !kindText.isBlank()) {
      try {
        kind = AppReviewTransparencyEventKind.parse(kindText);
      } catch (AppCatalogException _) {
        throw new PlatformApiException(
            400, "invalid_query_parameter", "kind is not a supported transparency event kind.");
      }
    }
    return new AppReviewTransparencyQuery(limit, cursor, appId, catalogId, reviewerKeyId, kind);
  }

  private static int parseLimit(String value) {
    if (value == null || value.isBlank()) {
      return AppReviewTransparencyQuery.DEFAULT_LIMIT;
    }
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException _) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "limit must be a positive integer.");
    }
  }

  private static void requireReviewGate(
      AppReviewTrustDecision decision, boolean reviewAcknowledged, boolean install) {
    Map<String, Object> reviewTrust = decision.toJsonValue();
    String blockField = install ? "blocksInstall" : "blocksUpdate";
    String action = install ? "Install" : "Update";
    if (Boolean.TRUE.equals(reviewTrust.get(blockField))) {
      throw new PlatformApiException(
          409, reviewGateFailureCode(reviewTrust), action + " blocked by app review policy.");
    }
    if (Boolean.TRUE.equals(reviewTrust.get("requiresAcknowledgement")) && !reviewAcknowledged) {
      throw new PlatformApiException(
          409,
          reviewGateFailureCode(reviewTrust),
          action + " requires explicit acknowledgement of the review trust decision.");
    }
  }

  private static void requireSecurityGate(
      AppCatalogSecurityDecision decision, boolean securityAcknowledged, boolean install) {
    Map<String, Object> securityDecision = decision.toJsonValue();
    String action = install ? "Install" : "Update";
    if (ERROR_APP_SECURITY_DENYLISTED.equals(securityGateFailureCode(securityDecision))) {
      throw new PlatformApiException(
          409, ERROR_APP_SECURITY_DENYLISTED, action + " blocked by app security denylist.");
    }
    String blockField = install ? "blocksInstall" : "blocksUpdate";
    if (Boolean.TRUE.equals(securityDecision.get(blockField))) {
      throw new PlatformApiException(
          409, ERROR_APP_SECURITY_BLOCKED, action + " blocked by app security policy.");
    }
    if (Boolean.TRUE.equals(securityDecision.get("requiresAcknowledgement"))
        && !securityAcknowledged) {
      throw new PlatformApiException(
          409,
          ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED,
          action + " requires explicit acknowledgement of the security advisory.");
    }
  }

  private static boolean reviewAcknowledgementStillApplies(
      AppReviewTrustDecision initialDecision,
      AppReviewTrustDecision preparedDecision,
      boolean reviewAcknowledged) {
    return reviewAcknowledged && initialDecision.equals(preparedDecision);
  }

  private static boolean securityAcknowledgementStillApplies(
      AppCatalogSecurityDecision initialDecision,
      AppCatalogSecurityDecision preparedDecision,
      boolean securityAcknowledged) {
    return securityAcknowledged && initialDecision.equals(preparedDecision);
  }

  private static String securityGateFailureCode(Map<String, Object> securityDecision) {
    Object statusValue = securityDecision.get(STATUS_FIELD);
    if ("denylisted".equals(statusValue)) {
      return ERROR_APP_SECURITY_DENYLISTED;
    }
    return ERROR_APP_SECURITY_BLOCKED;
  }

  private static String reviewGateFailureCode(Map<String, Object> reviewTrust) {
    Object statusValue = reviewTrust.get(STATUS_FIELD);
    if (!(statusValue instanceof String status)) {
      return ERROR_APP_REVIEW_UNTRUSTED;
    }
    return switch (status) {
      case "missing_receipt", "publisher_claim_only", "not_configured" -> ERROR_APP_REVIEW_MISSING;
      case "artifact_mismatch", "app_mismatch" -> ERROR_APP_REVIEW_MISMATCH;
      case "expired", "reviewer_expired", "retired_reviewer" -> ERROR_APP_REVIEW_EXPIRED;
      case "trusted_rejected" -> ERROR_APP_REVIEW_REJECTED;
      default -> ERROR_APP_REVIEW_UNTRUSTED;
    };
  }

  private Map<String, Object> summarizeCatalog(AppCatalogSourceSnapshot snapshot) {
    String sourceKind = sourceKind(snapshot);
    String refreshedAt = snapshot.refreshedAt().toString();
    String lastSuccessfulRefreshAt =
        timestampField(snapshot, LAST_SUCCESSFUL_REFRESH_AT_FIELD, refreshedAt);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(16);
    json.put(CATALOG_ID_FIELD, snapshot.catalogId());
    json.put("name", snapshot.name());
    json.put(SOURCE_FIELD, snapshot.sourceUri().toString());
    json.put(SOURCE_TYPE_FIELD, sourceKind);
    json.put(SOURCE_KIND_FIELD, sourceKind);
    json.put("generatedAt", snapshot.generatedAt().toString());
    json.put("appCount", snapshot.appCount());
    json.put("addedAt", snapshot.addedAt().toString());
    json.put("refreshedAt", refreshedAt);
    json.put(LAST_ATTEMPT_AT_FIELD, timestampField(snapshot, LAST_ATTEMPT_AT_FIELD, refreshedAt));
    json.put(LAST_SUCCESSFUL_REFRESH_AT_FIELD, lastSuccessfulRefreshAt);
    json.put(LAST_FETCH_STATUS_FIELD, lastFetchStatus(snapshot));
    json.put(LAST_FETCH_ERROR_CODE_FIELD, stringField(snapshot, LAST_FETCH_ERROR_CODE_FIELD, null));
    json.put(
        LAST_FETCH_ERROR_MESSAGE_FIELD,
        stringField(snapshot, LAST_FETCH_ERROR_MESSAGE_FIELD, null));
    json.put(
        LAST_RESOLVED_URI_FIELD,
        stringField(snapshot, LAST_RESOLVED_URI_FIELD, snapshot.sourceUri().toString()));
    json.put("signatureKeyId", snapshot.signatureKeyId().orElse(null));
    return json;
  }

  private static String sourceKind(AppCatalogSourceSnapshot snapshot) {
    String explicitKind = stringField(snapshot, SOURCE_KIND_FIELD, null);
    if (explicitKind != null) {
      return explicitKind.toLowerCase(Locale.ROOT);
    }
    String scheme = snapshot.sourceUri().getScheme();
    return scheme == null || scheme.isBlank()
        ? VERSION_STATUS_UNKNOWN
        : scheme.toLowerCase(Locale.ROOT);
  }

  private static String timestampField(
      AppCatalogSourceSnapshot snapshot, String accessorName, String fallback) {
    Object value = snapshotAccessorValue(snapshot, accessorName);
    if (value == null) {
      return fallback;
    }
    if (value instanceof Instant instant) {
      return instant.toString();
    }
    String text = value.toString();
    return text.isBlank() ? fallback : text;
  }

  private static String stringField(
      AppCatalogSourceSnapshot snapshot, String accessorName, String fallback) {
    Object value = snapshotAccessorValue(snapshot, accessorName);
    if (value == null) {
      return fallback;
    }
    String text = value instanceof Enum<?> enumValue ? enumValue.name() : value.toString();
    text = text.trim();
    return text.isEmpty() ? fallback : text;
  }

  private static String lastFetchStatus(AppCatalogSourceSnapshot snapshot) {
    return stringField(snapshot, LAST_FETCH_STATUS_FIELD, FETCH_STATUS_SUCCESS)
        .toLowerCase(Locale.ROOT);
  }

  private static Object snapshotAccessorValue(
      AppCatalogSourceSnapshot snapshot, String accessorName) {
    try {
      Method method = snapshot.getClass().getMethod(accessorName);
      Object value = method.invoke(snapshot);
      if (value instanceof Optional<?> optional) {
        return optional.orElse(null);
      }
      return value;
    } catch (ReflectiveOperationException | SecurityException _) {
      return null;
    }
  }

  private Map<String, Object> summarizeEntry(String catalogId, AppCatalogEntry entry) {
    return summarizeEntry(catalogId, entry, false);
  }

  private Map<String, Object> summarizeEntry(
      String catalogId, AppCatalogEntry entry, boolean tolerateInstalledReadFailure) {
    InstalledSummary installedSummary =
        installedForSummary(entry.appId(), tolerateInstalledReadFailure);
    InstalledAppSnapshot installed = installedSummary.snapshot();
    RunningAppSnapshot running = appHost.status(entry.appId()).orElse(null);
    String installedVersion = installed == null ? null : installed.manifest().appVersion();
    boolean installedPresent = installed != null || installedSummary.readFailed();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(29);
    json.put(APP_ID_FIELD, entry.appId());
    json.put("name", entry.name());
    json.put("version", entry.version());
    json.put("summary", entry.summary());
    json.put("homepage", entry.homepage().map(URI::toString).orElse(null));
    json.put(SOURCE_FIELD, entry.source().map(URI::toString).orElse(null));
    json.put("license", entry.license().orElse(null));
    json.put("categories", entry.categories());
    json.put("channel", entry.productionMetadata().channel().catalogValue());
    json.put("supportStatus", entry.productionMetadata().supportStatus().catalogValue());
    json.put("maintenance", summarizeMaintenance(entry.maintenanceMetadata()));
    json.put("deprecation", summarizeDeprecation(entry.productionMetadata()));
    json.put("securityAdvisories", summarizeSecurityAdvisories(entry.productionMetadata()));
    json.put(SECURITY_DECISION_FIELD, targetSecurityDecision(catalogId, entry).toJsonValue());
    json.put(
        "installedSecurityDecision",
        installed == null
            ? AppCatalogSecurityDecision.OK.toJsonValue()
            : installedSecurityDecision(entry.appId(), installedVersion).toJsonValue());
    json.put("review", summarizeReview(entry.review()));
    json.put("thirdPartyReview", summarizeThirdPartyReview(entry.review()));
    json.put(REVIEW_TRUST_FIELD, reviewTrust(entry).toJsonValue());
    json.put("permissions", entry.permissions());
    json.put("permissionRationales", entry.permissionRationales());
    json.put("compatibility", summarizeCompatibility(entry.compatibility()));
    json.put(
        "apiCompatibility",
        apiCompatibility(entry.compatibility().apiCompatibility(), entry.permissions()));
    json.put("changelog", summarizeChangelog(entry.changelog()));
    json.put("screenshots", entry.screenshots().stream().map(URI::toString).toList());
    json.put("bundle", summarizeBundle(entry));
    json.put(INSTALLED_FIELD, installedPresent);
    json.put("installedState", installedState(installedSummary, installed));
    json.put(INSTALLED_VERSION_FIELD, installedVersion);
    json.put(
        "versionDifferent", versionDifferent(entry.version(), installedVersion, installedPresent));
    json.put(
        "updateAvailable",
        updateAvailable(entry.version(), installedVersion, installedPresent).orElse(null));
    json.put("versionStatus", versionStatus(entry.version(), installedVersion, installedPresent));
    json.put("permissionDelta", summarizePermissionDelta(entry.permissions(), installed));
    json.put("running", running != null);
    json.put("pid", running == null ? null : running.pid());
    json.put("startedAt", running == null ? null : running.startedAt().toString());
    return json;
  }

  private InstalledAppSnapshot installed(String appId) {
    return installedForSummary(appId, false).snapshot();
  }

  private static String installedState(
      InstalledSummary installedSummary, InstalledAppSnapshot installed) {
    if (installedSummary.readFailed()) {
      return "unreadable_manifest";
    }
    return installed == null ? VERSION_STATUS_NOT_INSTALLED : VERSION_STATUS_INSTALLED;
  }

  private InstalledSummary installedForSummary(String appId, boolean tolerateReadFailure) {
    try {
      return new InstalledSummary(appHost.describe(appId).orElse(null), false);
    } catch (IOException _) {
      if (tolerateReadFailure) {
        return new InstalledSummary(null, true);
      }
      throw internalError("Failed to read installed apps.");
    }
  }

  private record InstalledSummary(InstalledAppSnapshot snapshot, boolean readFailed) {}

  private static Map<String, Object> summarizeBundle(AppCatalogEntry entry) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("uri", entry.bundleUri().toString());
    json.put("type", entry.bundleType());
    json.put("sizeBytes", entry.bundleSizeBytes());
    json.put("sha256", entry.bundleSha256());
    return json;
  }

  private static Map<String, Object> summarizeReview(AppCatalogReviewMetadata review) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(STATUS_FIELD, review.status().catalogValue());
    json.put("note", review.note().orElse(null));
    json.put(ADVISORY_FIELD, true);
    return json;
  }

  private static Map<String, Object> summarizeThirdPartyReview(AppCatalogReviewMetadata review) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
    json.put(STATUS_FIELD, review.status().catalogValue());
    json.put("submissionId", review.submissionId().orElse(null));
    json.put("submissionSha256", review.submissionSha256().orElse(null));
    json.put("preReviewStatus", review.preReviewStatus().orElse(null));
    json.put("preReviewSha256", review.preReviewSha256().orElse(null));
    json.put(REVIEWER_KEY_ID_FIELD, review.reviewerKeyId().orElse(null));
    json.put("reviewerPolicy", review.reviewerPolicy().orElse(null));
    json.put("receiptFingerprintSha256", review.receiptFingerprintSha256().orElse(null));
    json.put("decisionReasonSha256", review.decisionReasonSha256().orElse(null));
    json.put("resubmissionOf", review.resubmissionOf().orElse(null));
    json.put("nonProduction", review.nonProduction());
    json.put("hasSubmissionMetadata", review.hasSubmissionReviewFields());
    json.put(ADVISORY_FIELD, true);
    return json;
  }

  private Map<String, Object> summarizeCompatibility(
      AppCatalogCompatibilityMetadata compatibility) {
    String minimumVersion = compatibility.minimumCryptaVersion();
    String maximumVersion = compatibility.maximumCryptaVersion();
    String currentVersion = currentCryptaVersion();
    CompatibilityResult result =
        compatibilityResult(minimumVersion, maximumVersion, currentVersion);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("minimumCryptaVersion", minimumVersion);
    json.put("maximumCryptaVersion", maximumVersion);
    json.put("currentCryptaVersion", currentVersion);
    json.put(COMPATIBILITY_SATISFIED, result.satisfied());
    json.put(ADVISORY_FIELD, true);
    json.put(STATUS_FIELD, result.status());
    return json;
  }

  private static Map<String, Object> summarizeDeprecation(AppCatalogProductionMetadata metadata) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(STATUS_FIELD, metadata.deprecationStatus().catalogValue());
    json.put("message", metadata.deprecationMessage().orElse(null));
    json.put("replacementAppId", metadata.replacementAppId().orElse(null));
    return json;
  }

  private static Map<String, Object> summarizeMaintenance(AppCatalogMaintenanceMetadata metadata) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("owner", metadata.owner().orElse(null));
    json.put("ownerUri", metadata.ownerUri().map(URI::toString).orElse(null));
    json.put("supportLevel", metadata.supportLevel().map(SupportLevel::catalogValue).orElse(null));
    json.put(
        "dataSchemaPolicy",
        metadata.dataSchemaPolicy().map(DataSchemaPolicy::catalogValue).orElse(null));
    json.put(
        "migrationPolicy",
        metadata.migrationPolicy().map(MigrationPolicy::catalogValue).orElse(null));
    json.put(
        "backupRestore",
        metadata.backupRestore().map(BackupRestoreSupport::catalogValue).orElse(null));
    json.put(
        "securityPolicy", metadata.securityPolicy().map(SecurityPolicy::catalogValue).orElse(null));
    json.put(
        "deprecationPolicy",
        metadata.deprecationPolicy().map(DeprecationPolicy::catalogValue).orElse(null));
    json.put("supportUri", metadata.supportUri().map(URI::toString).orElse(null));
    return json;
  }

  private static List<Map<String, Object>> summarizeSecurityAdvisories(
      AppCatalogProductionMetadata metadata) {
    return metadata.securityAdvisories().stream()
        .map(AppCatalogsApiHandler::summarizeSecurityAdvisory)
        .toList();
  }

  private static Map<String, Object> summarizeSecurityAdvisory(
      AppCatalogSecurityAdvisory advisory) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("id", advisory.id());
    json.put("uri", advisory.uri().toString());
    return json;
  }

  private static Map<String, Object> summarizeChangelog(AppCatalogChangelog changelog) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("summary", changelog.summary().orElse(null));
    json.put("uri", changelog.uri().map(URI::toString).orElse(null));
    return json;
  }

  private static Map<String, Object> summarizePermissionDelta(
      List<String> catalogPermissions, InstalledAppSnapshot installed) {
    Set<String> catalog = new LinkedHashSet<>(catalogPermissions);
    Set<String> local =
        installed == null ? Set.of() : new LinkedHashSet<>(installed.manifest().permissions());
    List<String> added = new ArrayList<>();
    List<String> removed = new ArrayList<>();
    List<String> unchanged = new ArrayList<>();
    for (String permission : catalog) {
      if (local.contains(permission)) {
        unchanged.add(permission);
      } else {
        added.add(permission);
      }
    }
    for (String permission : local) {
      if (!catalog.contains(permission)) {
        removed.add(permission);
      }
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("added", List.copyOf(added));
    json.put("removed", List.copyOf(removed));
    json.put("unchanged", List.copyOf(unchanged));
    return json;
  }

  private String currentCryptaVersion() {
    try {
      String value = currentCryptaVersionSupplier.get();
      return value == null || value.isBlank() ? null : value;
    } catch (RuntimeException _) {
      return null;
    }
  }

  private static boolean versionDifferent(
      String catalogVersion, String installedVersion, boolean installed) {
    if (!installed) {
      return false;
    }
    if (catalogVersion == null || installedVersion == null) {
      return false;
    }
    return !catalogVersion.equals(installedVersion);
  }

  private static Optional<Boolean> updateAvailable(
      String catalogVersion, String installedVersion, boolean installed) {
    if (!installed) {
      return Optional.of(false);
    }
    if (catalogVersion == null || installedVersion == null) {
      return Optional.empty();
    }
    if (catalogVersion.equals(installedVersion)) {
      return Optional.of(false);
    }
    Integer comparison = compareDottedNumericVersions(catalogVersion, installedVersion);
    return comparison == null ? Optional.empty() : Optional.of(comparison > 0);
  }

  private static String versionStatus(
      String catalogVersion, String installedVersion, boolean installed) {
    if (!installed) {
      return VERSION_STATUS_NOT_INSTALLED;
    }
    if (catalogVersion == null || installedVersion == null) {
      return VERSION_STATUS_UNKNOWN;
    }
    return versionDifferent(catalogVersion, installedVersion, true)
        ? VERSION_STATUS_DIFFERENT
        : VERSION_STATUS_CURRENT;
  }

  private static CompatibilityResult compatibilityResult(
      String minimumVersion, String maximumVersion, String currentVersion) {
    if (minimumVersion == null && maximumVersion == null) {
      return new CompatibilityResult(true, COMPATIBILITY_NOT_DECLARED);
    }
    if (currentVersion == null) {
      return new CompatibilityResult(null, COMPATIBILITY_UNKNOWN);
    }
    Integer minimumComparison =
        minimumVersion == null
            ? Integer.valueOf(0)
            : compareDottedNumericVersions(currentVersion, minimumVersion);
    Integer maximumComparison =
        maximumVersion == null
            ? Integer.valueOf(0)
            : compareDottedNumericVersions(currentVersion, maximumVersion);
    if (minimumComparison == null || maximumComparison == null) {
      return new CompatibilityResult(null, COMPATIBILITY_UNKNOWN);
    }
    boolean satisfied = minimumComparison >= 0 && maximumComparison <= 0;
    return new CompatibilityResult(
        satisfied, satisfied ? COMPATIBILITY_SATISFIED : COMPATIBILITY_NOT_SATISFIED);
  }

  private static Integer compareDottedNumericVersions(String left, String right) {
    List<Integer> leftParts = parseDottedNumericVersion(left);
    List<Integer> rightParts = parseDottedNumericVersion(right);
    if (leftParts.isEmpty() || rightParts.isEmpty()) {
      return null;
    }
    int count = Math.max(leftParts.size(), rightParts.size());
    for (int index = 0; index < count; index++) {
      int leftPart = index < leftParts.size() ? leftParts.get(index) : 0;
      int rightPart = index < rightParts.size() ? rightParts.get(index) : 0;
      if (leftPart != rightPart) {
        return Integer.compare(leftPart, rightPart);
      }
    }
    return 0;
  }

  private static List<Integer> parseDottedNumericVersion(String version) {
    if (version == null || version.isBlank()) {
      return List.of();
    }
    String[] tokens = version.trim().split("\\.", -1);
    List<Integer> parts = new ArrayList<>(tokens.length);
    for (String token : tokens) {
      if (token.isBlank() || !token.chars().allMatch(Character::isDigit)) {
        return List.of();
      }
      try {
        parts.add(Integer.parseInt(token));
      } catch (NumberFormatException _) {
        return List.of();
      }
    }
    return List.copyOf(parts);
  }

  private static Map<String, Object> apiCompatibility(
      AppApiCompatibilityMetadata metadata, List<String> permissions) {
    return PlatformApiContractVerifier.summarize(
        metadata, permissions, PlatformApiContract.current());
  }

  private static boolean reviewAcknowledged(Map<String, List<String>> queryParameters) {
    String value =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_REVIEW_ACKNOWLEDGED);
    if (value == null || value.isBlank()) {
      return false;
    }
    if ("true".equalsIgnoreCase(value.trim())) {
      return true;
    }
    if ("false".equalsIgnoreCase(value.trim())) {
      return false;
    }
    throw new PlatformApiException(
        400, "invalid_query_parameter", PARAM_REVIEW_ACKNOWLEDGED + " must be 'true' or 'false'.");
  }

  private static boolean securityAcknowledged(Map<String, List<String>> queryParameters) {
    String value =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_SECURITY_ACKNOWLEDGED);
    if (value == null || value.isBlank()) {
      return false;
    }
    if ("true".equalsIgnoreCase(value.trim())) {
      return true;
    }
    if ("false".equalsIgnoreCase(value.trim())) {
      return false;
    }
    throw new PlatformApiException(
        400,
        "invalid_query_parameter",
        PARAM_SECURITY_ACKNOWLEDGED + " must be 'true' or 'false'.");
  }

  private static Map<String, Object> summarizeInstalledApp(AppManifest manifest) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
    json.put(APP_ID_FIELD, manifest.appId());
    json.put("name", manifest.appName());
    json.put("version", manifest.appVersion());
    json.put("uiMode", manifest.uiMode().manifestValue());
    json.put("uiEntry", manifest.uiEntry());
    json.put("uiUrl", AppUiPaths.uiUrl(manifest));
    json.put("permissions", manifest.permissions());
    json.put(
        "apiCompatibility", apiCompatibility(manifest.apiCompatibility(), manifest.permissions()));
    json.put(INSTALLED_FIELD, true);
    json.put("running", false);
    json.put("pid", null);
    json.put("startedAt", null);
    return json;
  }

  private PlatformApiException catalogFailure(AppCatalogException exception) {
    return switch (exception.errorCode()) {
      case "catalog_not_found", "app_not_found" ->
          new PlatformApiException(404, exception.errorCode(), exception.getMessage());
      case "catalog_conflict" ->
          new PlatformApiException(409, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_unavailable", "artifact_fetch_unavailable" ->
          new PlatformApiException(503, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_failed", "artifact_download_failed" ->
          new PlatformApiException(502, exception.errorCode(), exception.getMessage());
      default -> new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    };
  }

  private PlatformApiException installFailure(AppHostException exception) {
    if (isAlreadyInstalledFailure(exception)) {
      return conflict(alreadyInstalledMessage(exception));
    }
    if (exception instanceof AppBundleVerificationException) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, "Catalog app bundle failed trusted verification.");
    }
    if (isInvalidAppBundleFailure(exception)) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, APPHOST_BUNDLE_VALIDATION_MESSAGE);
    }
    return internalError(INSTALL_FAILED_MESSAGE);
  }

  private PlatformApiException updateFailure(String appId, AppHostException exception) {
    if (isRunningUpdateFailure(exception) || appHost.status(appId).isPresent()) {
      return conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + appId);
    }
    if (isMissingAppFailure(exception)) {
      return new PlatformApiException(404, "app_not_found", "App not found.");
    }
    if (exception instanceof AppBundleVerificationException) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, "Catalog app bundle failed trusted verification.");
    }
    if (isInvalidAppBundleFailure(exception)) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, APPHOST_BUNDLE_VALIDATION_MESSAGE);
    }
    return internalError(UPDATE_FAILED_MESSAGE);
  }

  private static boolean isInvalidAppBundleFailure(AppHostException failure) {
    if (failure instanceof network.crypta.platform.apphost.manifest.AppManifestException) {
      return true;
    }
    String message = failure.getMessage();
    if (message == null || message.isBlank()) {
      return false;
    }
    return message.startsWith("stagedAppDirectory ")
        || message.startsWith("staging directory ")
        || message.startsWith("copied manifest ")
        || message.startsWith("copied app.exec ")
        || message.startsWith("app.ui.entry ")
        || message.startsWith("app.exec ")
        || message.startsWith("staged app bundle ");
  }

  private static boolean isAlreadyInstalledFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_ALREADY_INSTALLED_PREFIX);
  }

  private static boolean isRunningUpdateFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(CANNOT_UPDATE_RUNNING_APP_PREFIX);
  }

  private static boolean isMissingAppFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_NOT_INSTALLED_PREFIX);
  }

  private static PlatformApiException conflict(String message) {
    return new PlatformApiException(409, "app_conflict", message);
  }

  private static PlatformApiException internalError(String message) {
    return new PlatformApiException(500, "internal_error", message);
  }

  private static String alreadyInstalledMessage(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? "App already installed." : message;
  }

  private record CompatibilityResult(Boolean satisfied, String status) {}
}
