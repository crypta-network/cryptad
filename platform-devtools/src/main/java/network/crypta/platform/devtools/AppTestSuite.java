package network.crypta.platform.devtools;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.platform.api.PlatformApiBaselineRegistry;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractJson;
import network.crypta.platform.api.PlatformApiContractVerifier.CompatibilityVerificationResult;
import network.crypta.platform.api.PlatformApiContractVerifier;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogWriter;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.devtools.devserver.CryptaAppDevServer;
import network.crypta.platform.devtools.devserver.DevServerConfig;
import network.crypta.platform.devtools.devserver.DevServerStaticAssets;

/**
 * Composite offline developer check suite for staged app bundles.
 *
 * <p>This class backs {@code crypta-app test}. It runs the same focused checks a third-party app
 * developer is expected to run before signing and publishing a bundle: bundle validation, static UI
 * linting, Platform API compatibility, static asset safety, a mock bootstrap/API smoke test, and
 * optional catalog descriptor sanity. The suite is intentionally offline. It starts only the local
 * loopback mock server and never connects to a Crypta node, FCP endpoint, or public network.
 *
 * <p>Checks run in a stable order and are converted into sanitized {@link AppTestCheck} values.
 * Bundle validation is the gate for manifest-dependent checks; if the bundle cannot be trusted, the
 * report stops after that failure. Strict mode affects status promotion, not the shape of the
 * report: warnings remain visible as warning checks, but they can make the aggregate status fail.
 */
final class AppTestSuite {
  /** JSON field extractor used only for the local bootstrap smoke response. */
  private static final Pattern BOOTSTRAP_SESSION_PATTERN =
      Pattern.compile("\"browserSessionToken\"\\s*:\\s*\"([^\"]+)\"");

  /** Stable check id for bundle structure and manifest validation. */
  private static final String CHECK_BUNDLE_VALIDATE = "bundle.validate";

  /** Stable check id for static UI linting. */
  private static final String CHECK_UI_LINT = "ui.lint";

  /** Stable check id for Platform API compatibility verification. */
  private static final String CHECK_API_COMPAT = "api.compat";

  /** Stable check id for local static asset serving safety. */
  private static final String CHECK_STATIC_ASSETS_SAFETY = "static-assets.safety";

  /** Stable check id for local bootstrap and mock API smoke testing. */
  private static final String CHECK_DEV_BOOTSTRAP_SMOKE = "dev.bootstrap-smoke";

  /** Stable check id for optional catalog descriptor parsing. */
  private static final String CHECK_CATALOG_ENTRY_SANITY = "catalog-entry.sanity";

  /** HTTP header used by local smoke requests to ask for predictable content types. */
  private static final String ACCEPT_HEADER = "Accept";

  /** Prevents construction of this stateless test-suite coordinator. */
  private AppTestSuite() {}

  /**
   * Runs the offline app test suite for one staged bundle.
   *
   * <p>The returned report is always safe to print or serialize through {@link AppTestReportJson}.
   * If bundle validation fails before a manifest can be parsed, the report uses empty app identity
   * fields and a failed aggregate status. Otherwise, the manifest controls which static-app checks
   * apply and supplies the app id/version for the final report.
   *
   * @param request normalized or relative CLI request values for the bundle under test
   * @return sanitized deterministic report for terminal and JSON output
   */
  static AppTestReport run(Request request) {
    List<AppTestCheck> checks = new ArrayList<>();
    ValidationHolder validationHolder = new ValidationHolder();
    checks.add(runCheck(CHECK_BUNDLE_VALIDATE, () -> validateBundle(request, validationHolder)));
    BundleValidation validation = validationHolder.validation;
    if (validation != null) {
      AppBundleManifest manifest = validation.manifest();
      if (manifest.uiMode() == AppUiMode.STATIC) {
        checks.add(runCheck(CHECK_UI_LINT, () -> lintUi(request)));
      } else {
        checks.add(new AppTestCheck(CHECK_UI_LINT, AppTestStatus.PASS, "UI lint not applicable."));
      }
      checks.add(runCheck(CHECK_API_COMPAT, () -> verifyCompatibility(request, manifest)));
      checks.add(runCheck(CHECK_STATIC_ASSETS_SAFETY, () -> checkStaticAssets(request, manifest)));
      if (manifest.uiMode() == AppUiMode.STATIC) {
        checks.add(runCheck(CHECK_DEV_BOOTSTRAP_SMOKE, () -> smokeDevServer(request)));
      }
      if (request.catalogEntry() != null) {
        checks.add(runCheck(CHECK_CATALOG_ENTRY_SANITY, () -> inspectCatalogEntry(request)));
      }
      return reportFor(request, manifest, checks);
    }
    return new AppTestReport(1, "", "", AppTestStatus.FAIL, checks);
  }

  /**
   * Validates bundle structure and captures the parsed manifest for later checks.
   *
   * @param request suite request containing the staged bundle directory and strict-mode flag
   * @param validationHolder mutable holder used to pass successful validation to later checks
   * @return sanitized check result describing validation success, warning, or failure
   * @throws IOException if bundle metadata or staged files cannot be read
   */
  private static AppTestCheck validateBundle(Request request, ValidationHolder validationHolder)
      throws IOException {
    validationHolder.validation = BundleValidator.validate(request.bundleDir(), request.strict());
    if (validationHolder.validation.permissionLint().hasUnknownPermissions()) {
      return new AppTestCheck(
          CHECK_BUNDLE_VALIDATE,
          request.strict() ? AppTestStatus.FAIL : AppTestStatus.WARN,
          "Bundle is valid with unknown permission warnings.");
    }
    return new AppTestCheck(CHECK_BUNDLE_VALIDATE, AppTestStatus.PASS, "Bundle validation passed.");
  }

  /**
   * Runs the static UI linter for a bundle that declares {@code app.ui.mode=static}.
   *
   * @param request suite request containing bundle location and strict-mode behavior
   * @return check result that reports lint pass, warning promotion, or lint failure
   * @throws IOException if the linter cannot read static UI files
   */
  private static AppTestCheck lintUi(Request request) throws IOException {
    AppUiLintResult result = AppUiLinter.lint(request.bundleDir(), request.strict());
    if (result.hasErrors()) {
      return new AppTestCheck(
          CHECK_UI_LINT,
          AppTestStatus.FAIL,
          "UI lint failed: " + result.errorCount() + " error(s).");
    }
    if (result.warningCount() > 0) {
      return new AppTestCheck(
          CHECK_UI_LINT,
          request.strict() ? AppTestStatus.FAIL : AppTestStatus.WARN,
          "UI lint reported " + result.warningCount() + " warning(s).");
    }
    return new AppTestCheck(CHECK_UI_LINT, AppTestStatus.PASS, "UI lint passed.");
  }

  /**
   * Verifies manifest-declared permissions and API compatibility against a Platform API contract.
   *
   * @param request suite request with optional contract override and strict-mode flag
   * @param manifest validated app manifest from bundle validation
   * @return check result for compatibility findings under normal or strict mode
   * @throws IOException if the contract override cannot be loaded or parsed
   */
  private static AppTestCheck verifyCompatibility(Request request, AppBundleManifest manifest)
      throws IOException {
    ContractSelection selection = loadContract(request.contract(), request.baselineRegistry());
    CompatibilityVerificationResult result =
        PlatformApiContractVerifier.verify(
            manifest.apiCompatibility(),
            manifest.permissions(),
            selection.contract(),
            selection.registry(),
            request.strict());
    if (result.hasErrors()) {
      return new AppTestCheck(CHECK_API_COMPAT, AppTestStatus.FAIL, "API compatibility failed.");
    }
    if (!result.findings().isEmpty()) {
      return new AppTestCheck(
          CHECK_API_COMPAT,
          request.strict() ? AppTestStatus.FAIL : AppTestStatus.WARN,
          "API compatibility reported " + result.findings().size() + " finding(s).");
    }
    return new AppTestCheck(CHECK_API_COMPAT, AppTestStatus.PASS, "API compatibility passed.");
  }

  /**
   * Loads the contract used by compatibility verification.
   *
   * @param contractFile optional user-supplied contract JSON, or {@code null} for the current
   *     built-in validation contract
   * @param registryFile optional named-baseline registry paired with the supplied contract
   * @return parsed and registry-bound Platform API inputs used for this suite run
   * @throws IOException if a user-supplied contract or registry file cannot be read
   */
  private static ContractSelection loadContract(Path contractFile, Path registryFile)
      throws IOException {
    PlatformApiBaselineRegistry registry =
        registryFile == null
            ? PlatformApiBaselineRegistry.current()
            : PlatformApiContractJson.parseBaselineRegistry(
                Files.readString(registryFile, StandardCharsets.UTF_8));
    if (contractFile == null) {
      return new ContractSelection(
          DevtoolsCapabilityVocabulary.currentValidationContract(), registry);
    }
    String json = Files.readString(contractFile, StandardCharsets.UTF_8);
    PlatformApiContract contract = PlatformApiContractJson.parse(json);
    PlatformApiContractJson.verifyBaselineRegistrySummary(json, registry);
    return new ContractSelection(contract, registry);
  }

  /**
   * Checks whether static UI entry files are safe for the local dev server to expose.
   *
   * @param request suite request containing the staged bundle root
   * @param manifest validated app manifest that declares the UI mode and entry path
   * @return check result explaining whether static asset serving is applicable and safe
   * @throws IOException if filesystem metadata cannot be read safely
   */
  private static AppTestCheck checkStaticAssets(Request request, AppBundleManifest manifest)
      throws IOException {
    if (manifest.uiMode() != AppUiMode.STATIC) {
      return new AppTestCheck(
          CHECK_STATIC_ASSETS_SAFETY, AppTestStatus.PASS, "Static UI not declared.");
    }
    DevServerStaticAssets.checkStaticAssetSafety(request.bundleDir(), manifest);
    return new AppTestCheck(
        CHECK_STATIC_ASSETS_SAFETY, AppTestStatus.PASS, "Static assets are safe to serve.");
  }

  /**
   * Starts the loopback mock dev server and exercises bootstrap, API, and static UI routes.
   *
   * <p>The smoke test proves that the generated bootstrap JSON includes a usable browser-session
   * token, that the mock API enforces that token, and that the app entry route can serve HTML. It
   * does not test browser rendering, hot reload, live Crypta insertion, or real AppHost behavior.
   *
   * @param request suite request containing the staged static bundle
   * @return passing check result when all smoke requests return HTTP 200
   * @throws IOException if the server cannot start or a smoke response cannot be read
   * @throws InterruptedException if the thread is interrupted while waiting for a smoke response
   */
  private static AppTestCheck smokeDevServer(Request request)
      throws IOException, InterruptedException {
    try (CryptaAppDevServer server =
            CryptaAppDevServer.start(
                new DevServerConfig(
                    request.bundleDir(), "127.0.0.1", 0, null, false, Duration.ofMinutes(5)));
        HttpClient client =
            HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .version(HttpClient.Version.HTTP_1_1)
                .build()) {
      HttpResponse<String> bootstrap =
          client.send(
              request(URI.create(server.bootstrapUrl()))
                  .header(ACCEPT_HEADER, "application/json")
                  .GET()
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      if (bootstrap.statusCode() != 200) {
        throw new AppDistributionException("bootstrap smoke returned " + bootstrap.statusCode());
      }
      String session = extractSession(bootstrap.body());
      HttpResponse<String> api =
          client.send(
              request(URI.create(server.apiRoot() + "queue"))
                  .header(ACCEPT_HEADER, "application/json")
                  .header("X-Crypta-App-Session", session)
                  .GET()
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      if (api.statusCode() != 200) {
        throw new AppDistributionException("mock API smoke returned " + api.statusCode());
      }
      HttpResponse<String> staticUi =
          client.send(
              request(URI.create(server.uiUrl())).header(ACCEPT_HEADER, "text/html").GET().build(),
              HttpResponse.BodyHandlers.ofString());
      if (staticUi.statusCode() != 200) {
        throw new AppDistributionException("static UI smoke returned " + staticUi.statusCode());
      }
      return new AppTestCheck(
          CHECK_DEV_BOOTSTRAP_SMOKE,
          AppTestStatus.PASS,
          "Bootstrap, mock API, and static UI passed.");
    }
  }

  /**
   * Extracts the mock browser-session token from bootstrap JSON.
   *
   * @param body bootstrap response body returned by the local dev server
   * @return non-blank browser-session token used for the smoke API request
   */
  private static String extractSession(String body) {
    Matcher matcher = BOOTSTRAP_SESSION_PATTERN.matcher(body);
    if (!matcher.find() || matcher.group(1).isBlank()) {
      throw new IllegalArgumentException("bootstrap response did not include a browser session");
    }
    return matcher.group(1);
  }

  /**
   * Creates an HTTP request builder with the suite's short smoke-test timeout.
   *
   * @param uri local loopback URI to request
   * @return request builder configured with a deterministic timeout
   */
  private static HttpRequest.Builder request(URI uri) {
    return HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5));
  }

  /**
   * Parses an optional catalog entry descriptor when the developer supplied one.
   *
   * @param request suite request containing the optional descriptor path
   * @return passing check result when the descriptor is accepted by catalog tooling
   * @throws IOException if the descriptor cannot be read or parsed
   */
  private static AppTestCheck inspectCatalogEntry(Request request) throws IOException {
    AppCatalogWriter.inspectEntryDescriptor(request.catalogEntry());
    return new AppTestCheck(
        CHECK_CATALOG_ENTRY_SANITY, AppTestStatus.PASS, "Catalog entry descriptor parsed.");
  }

  /**
   * Runs one suite operation and converts thrown exceptions into sanitized failed checks.
   *
   * @param id stable check identifier used when the operation fails before returning a result
   * @param operation operation that performs the check
   * @return the operation result or a failed check containing the redacted exception message
   */
  private static AppTestCheck runCheck(String id, CheckOperation operation) {
    try {
      return operation.run();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      return new AppTestCheck(id, AppTestStatus.FAIL, exception.getMessage());
    } catch (IOException | AppCatalogException | IllegalArgumentException exception) {
      return new AppTestCheck(id, AppTestStatus.FAIL, exception.getMessage());
    }
  }

  /**
   * Computes the aggregate report status and attaches validated app identity fields.
   *
   * @param request suite request whose strict flag controls warning promotion
   * @param manifest validated manifest used for app id and version
   * @param checks ordered check results collected during this suite run
   * @return immutable sanitized app test report
   */
  private static AppTestReport reportFor(
      Request request, AppBundleManifest manifest, List<AppTestCheck> checks) {
    AppTestStatus status = AppTestStatus.PASS;
    for (AppTestCheck check : checks) {
      if (check.status() == AppTestStatus.FAIL
          || (request.strict() && check.status() == AppTestStatus.WARN)) {
        status = AppTestStatus.FAIL;
        break;
      }
      if (check.status() == AppTestStatus.WARN) {
        status = AppTestStatus.WARN;
      }
    }
    return new AppTestReport(1, manifest.appId(), manifest.appVersion(), status, checks);
  }

  /** Operation adapter used so each check can be wrapped with consistent failure handling. */
  @FunctionalInterface
  private interface CheckOperation {
    /**
     * Runs the underlying check.
     *
     * @return sanitized check result produced by the operation
     * @throws IOException if the operation fails while reading bundle, API, or catalog inputs
     * @throws InterruptedException if the operation is interrupted while waiting for local HTTP
     */
    AppTestCheck run() throws IOException, InterruptedException;
  }

  /** Mutable bridge from the bundle validation check to later manifest-dependent checks. */
  private static final class ValidationHolder {
    /** Creates an empty holder before bundle validation has run. */
    private ValidationHolder() {}

    /** Successful bundle validation result, or {@code null} when validation failed. */
    private BundleValidation validation;
  }

  /** Contract and named-baseline authority selected for one compatibility check. */
  private record ContractSelection(
      PlatformApiContract contract, PlatformApiBaselineRegistry registry) {}

  /**
   * Input for one test suite run.
   *
   * <p>The CLI constructs this record from command-line options before invoking the suite. Paths
   * are normalized to absolute form once so lower-level checks can open files consistently, while
   * report generation still redacts any path text that escapes through diagnostics. A {@code null}
   * contract uses the built-in current Platform API contract, a {@code null} baseline registry uses
   * the built-in current registry, and a {@code null} catalog entry skips descriptor sanity
   * checking.
   *
   * @param bundleDir staged bundle directory to validate and, for static apps, serve locally
   * @param strict whether warnings should make the aggregate report fail
   * @param contract optional Platform API contract JSON used instead of the built-in contract
   * @param baselineRegistry optional named-baseline registry paired with the contract
   * @param catalogEntry optional catalog entry descriptor checked after manifest validation
   */
  record Request(
      Path bundleDir, boolean strict, Path contract, Path baselineRegistry, Path catalogEntry) {
    /**
     * Normalizes user-supplied paths for deterministic filesystem access.
     *
     * <p>The constructor does not require optional paths to exist because later checks own their
     * specific failure messages. This keeps the request layer simple and lets the report identify
     * the failing gate precisely.
     */
    Request {
      bundleDir = bundleDir.toAbsolutePath().normalize();
      if (contract != null) {
        contract = contract.toAbsolutePath().normalize();
      }
      if (baselineRegistry != null) {
        baselineRegistry = baselineRegistry.toAbsolutePath().normalize();
      }
      if (catalogEntry != null) {
        catalogEntry = catalogEntry.toAbsolutePath().normalize();
      }
    }
  }
}
