package network.crypta.platform.api.wizard;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.runtime.spi.FirstTimeWizardCurrentBandwidthLimits;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.Fields;

/**
 * First-time-wizard control-plane endpoints for Platform API v1.
 *
 * <p>This handler exposes the detached first-time-wizard snapshot and submission flow through the
 * Platform API without inventing a second onboarding model. It reuses the runtime SPI snapshot and
 * submission record directly, then performs transport-neutral validation that matches the current
 * shell-native wizard fields. The result is a form-oriented API surface that stays close to the
 * legacy workflow while remaining deterministic for JSON clients.
 *
 * <p>The handler is intentionally conservative about what it validates. It rejects malformed text
 * values, impossible bandwidth/storage choices, and wizard mutations that would silently normalize
 * unsupported live security states. It does not reimplement the daemon's full onboarding logic or
 * master-password flows; instead, it validates the request shape, preserves the current shell
 * contract, and delegates accepted submissions to the daemon-backed runtime port.
 *
 * <ul>
 *   <li>Snapshot reads return detached wizard defaults and the current security context.
 *   <li>Writes remain parameter-centric and mirror existing form semantics.
 *   <li>Conflicts are surfaced as stable API errors before the daemon applies the submission.
 * </ul>
 */
public final class FirstTimeWizardApiHandler {
  private static final String GIB_UNIT_SUFFIX = " GiB.";
  private static final String INVALID_GIB_VALUE_MESSAGE = "must be a valid GiB value.";
  private static final String INVALID_KIB_VALUE_MESSAGE = "must be a valid KiB value.";
  private static final long KIB = 1024L;
  private static final String KIB_UNIT_SUFFIX = " KiB.";
  private static final long MAX_INT_BACKED_BANDWIDTH_LIMIT_BYTES = Integer.MAX_VALUE;
  private static final int MAX_PASSWORD_LENGTH = 1024;
  private static final String MUST_BE_AT_LEAST = " must be at least ";
  private static final String MUST_BE_AT_MOST = " must be at most ";
  private static final String FIELD_OPERATION = "operation";
  private static final String PARAMETER_BANDWIDTH_MONTHLY_LIMIT_GIB = "bandwidthMonthlyLimitGiB";
  private static final String PARAMETER_CONNECT_TO_STRANGERS = "connectToStrangers";
  private static final String PARAMETER_DOWNLOAD_LIMIT_KIB = "downloadLimitKiB";
  private static final String PARAMETER_HAVE_MONTHLY_LIMIT = "haveMonthlyLimit";
  private static final String PARAMETER_KNOW_SOMEONE = "knowSomeone";
  private static final String PARAMETER_PASSWORD = "password";
  private static final String PARAMETER_PRESERVE_BANDWIDTH_SETTINGS = "preserveBandwidthSettings";
  private static final String PARAMETER_PRESERVE_CURRENT_NETWORK_THREAT_LEVEL =
      "preserveCurrentNetworkThreatLevel";
  private static final String PARAMETER_PRESERVE_CURRENT_PHYSICAL_THREAT_LEVEL =
      "preserveCurrentPhysicalThreatLevel";
  private static final String PARAMETER_SET_PASSWORD = "setPassword";
  private static final String PARAMETER_STORAGE_LIMIT_GIB = "storageLimitGiB";
  private static final String PARAMETER_UPLOAD_LIMIT_KIB = "uploadLimitKiB";

  /** Detached runtime port that supplies wizard snapshots and applies validated submissions. */
  private final FirstTimeWizardPort firstTimeWizardPort;

  /**
   * Creates a first-time-wizard API handler backed by the supplied runtime port.
   *
   * <p>The supplied port remains responsible for reading live wizard defaults, exposing the current
   * detached security snapshot, and applying validated submissions with the daemon's existing
   * onboarding semantics. This handler only adds request parsing, API-level validation, and stable
   * error mapping for the Platform API surface.
   *
   * @param firstTimeWizardPort detached wizard runtime port used for snapshot reads and validated
   *     submission application
   * @throws NullPointerException if {@code firstTimeWizardPort} is {@code null}
   */
  public FirstTimeWizardApiHandler(FirstTimeWizardPort firstTimeWizardPort) {
    this.firstTimeWizardPort = Objects.requireNonNull(firstTimeWizardPort, "firstTimeWizardPort");
  }

  /**
   * Returns the current detached first-time-wizard snapshot.
   *
   * <p>The returned map combines wizard defaults with the current detached security state so the
   * shell can render one coherent onboarding/reset panel. Fields such as bandwidth and storage
   * limits come from the runtime wizard snapshot, while the current network and physical threat
   * levels are read separately so callers can decide when the wizard should edit or preserve those
   * states.
   *
   * @return JSON-compatible wizard snapshot containing detached limits, detected defaults, and the
   *     current security-level context required by the shell
   */
  public Map<String, Object> snapshot() {
    FirstTimeWizardSnapshot snapshot = firstTimeWizardPort.snapshot();
    SecurityLevelsSnapshot securitySnapshot = firstTimeWizardPort.securitySnapshot();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(15);
    json.put("passwordAlreadySet", snapshot.passwordAlreadySet());
    json.put("opennetEnabled", firstTimeWizardPort.isOpennetEnabled());
    json.put("currentNetworkThreatLevel", securitySnapshot.networkThreatLevel().name());
    json.put("currentPhysicalThreatLevel", securitySnapshot.physicalThreatLevel().name());
    json.put("initialStorageLimitGiB", snapshot.initialStorageLimitGiB());
    json.put("minStorageLimitGiB", snapshot.minStorageLimitGiB());
    json.put("minStorageLimitBytes", snapshot.minStorageLimitBytes());
    json.put("maxStorageLimitGiB", snapshot.maxStorageLimitGiB());
    json.put("maxStorageLimitBytes", snapshot.maxStorageLimitBytes());
    json.put("legacyMaxStorageLimitBytes", snapshot.legacyMaxStorageLimitBytes());
    json.put("minBandwidthKiB", snapshot.minBandwidthKiB());
    json.put("maxUploadLimitKiB", snapshot.maxUploadLimitKiB());
    json.put("minBandwidthMonthlyLimitGiB", snapshot.minBandwidthMonthlyLimitGiB());
    json.put("detectedDownloadLimitKiB", snapshot.detectedDownloadLimitKiB());
    json.put("detectedUploadLimitKiB", snapshot.detectedUploadLimitKiB());
    putCurrentBandwidthLimits(json, snapshot.currentBandwidthLimits());
    json.put("autodetectedStorageLimitBytes", snapshot.autodetectedStorageLimitBytes());
    return json;
  }

  /**
   * Validates and applies one detached wizard submission.
   *
   * <p>The request stays parameter-oriented on purpose. Callers submit checkbox-style booleans and
   * raw text fields that match the existing form controls, and this handler validates only the
   * aspects that must be transport-neutral: required parameters, numeric ranges, password field
   * shape, and preserve-flag combinations for unsupported live security states. Accepted
   * submissions are then forwarded unchanged to the daemon-backed wizard port.
   *
   * @param queryParameters decoded request parameters for the current request
   * @return JSON-compatible mutation summary describing the accepted wizard submission
   * @throws PlatformApiException if the submission is malformed, conflicts with the current wizard
   *     state, or attempts to edit unsupported live security settings without the required preserve
   *     flags
   */
  public Map<String, Object> apply(Map<String, List<String>> queryParameters) {
    FirstTimeWizardSnapshot snapshot = firstTimeWizardPort.snapshot();
    SecurityLevelsSnapshot securitySnapshot = firstTimeWizardPort.securitySnapshot();
    FirstTimeWizardSubmission submission = parseSubmission(queryParameters, snapshot);
    validateCurrentSecurityState(securitySnapshot, submission);
    firstTimeWizardPort.applySubmission(submission);

    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(2);
    response.put(FIELD_OPERATION, "apply_submission");
    response.put("wizardApplied", true);
    return response;
  }

  private static void putCurrentBandwidthLimits(
      Map<String, Object> json, FirstTimeWizardCurrentBandwidthLimits currentBandwidthLimits) {
    if (currentBandwidthLimits == null) {
      json.put("currentBandwidthLimits", null);
      return;
    }
    LinkedHashMap<String, Object> currentBandwidthJson = LinkedHashMap.newLinkedHashMap(2);
    currentBandwidthJson.put("downloadBytes", currentBandwidthLimits.downloadBytes());
    currentBandwidthJson.put("uploadBytes", currentBandwidthLimits.uploadBytes());
    json.put("currentBandwidthLimits", currentBandwidthJson);
  }

  private static FirstTimeWizardSubmission parseSubmission(
      Map<String, List<String>> queryParameters, FirstTimeWizardSnapshot snapshot) {
    boolean knowSomeone = readCheckboxBoolean(queryParameters, PARAMETER_KNOW_SOMEONE);
    boolean connectToStrangers =
        readCheckboxBoolean(queryParameters, PARAMETER_CONNECT_TO_STRANGERS);
    boolean haveMonthlyLimit = readCheckboxBoolean(queryParameters, PARAMETER_HAVE_MONTHLY_LIMIT);
    boolean preserveBandwidthSettings =
        readCheckboxBoolean(queryParameters, PARAMETER_PRESERVE_BANDWIDTH_SETTINGS);
    boolean preserveCurrentNetworkThreatLevel =
        readCheckboxBoolean(queryParameters, PARAMETER_PRESERVE_CURRENT_NETWORK_THREAT_LEVEL);
    boolean preserveCurrentPhysicalThreatLevel =
        readCheckboxBoolean(queryParameters, PARAMETER_PRESERVE_CURRENT_PHYSICAL_THREAT_LEVEL);
    boolean setPassword = readCheckboxBoolean(queryParameters, PARAMETER_SET_PASSWORD);

    String downloadLimitKiB =
        haveMonthlyLimit || preserveBandwidthSettings
            ? optionalString(queryParameters, PARAMETER_DOWNLOAD_LIMIT_KIB)
            : PlatformApiParameters.requireString(queryParameters, PARAMETER_DOWNLOAD_LIMIT_KIB);
    String uploadLimitKiB =
        haveMonthlyLimit || preserveBandwidthSettings
            ? optionalString(queryParameters, PARAMETER_UPLOAD_LIMIT_KIB)
            : PlatformApiParameters.requireString(queryParameters, PARAMETER_UPLOAD_LIMIT_KIB);
    String bandwidthMonthlyLimitGiB =
        haveMonthlyLimit && !preserveBandwidthSettings
            ? PlatformApiParameters.requireString(
                queryParameters, PARAMETER_BANDWIDTH_MONTHLY_LIMIT_GIB)
            : optionalString(queryParameters, PARAMETER_BANDWIDTH_MONTHLY_LIMIT_GIB);
    String storageLimitGiB =
        PlatformApiParameters.requireString(queryParameters, PARAMETER_STORAGE_LIMIT_GIB);
    String password =
        setPassword
            ? PlatformApiParameters.requirePresentString(queryParameters, PARAMETER_PASSWORD)
            : optionalString(queryParameters, PARAMETER_PASSWORD);

    FirstTimeWizardSubmission submission =
        new FirstTimeWizardSubmission(
            knowSomeone,
            connectToStrangers,
            haveMonthlyLimit,
            preserveBandwidthSettings,
            preserveCurrentNetworkThreatLevel,
            preserveCurrentPhysicalThreatLevel,
            downloadLimitKiB,
            uploadLimitKiB,
            bandwidthMonthlyLimitGiB,
            storageLimitGiB,
            setPassword,
            password);
    validateSubmission(snapshot, submission);
    return submission;
  }

  private static void validateSubmission(
      FirstTimeWizardSnapshot snapshot, FirstTimeWizardSubmission submission) {
    validatePasswordFlowAvailability(snapshot, submission);
    validateStorageLimit(snapshot, submission.storageLimitGiB());
    if (submission.preserveBandwidthSettings()) {
      validatePassword(submission.setPassword(), submission.password());
      return;
    }
    if (submission.haveMonthlyLimit()) {
      validateMonthlyLimit(snapshot, submission.bandwidthMonthlyLimitGiB());
    } else {
      validateDownloadLimit(snapshot, submission.downloadLimitKiB());
      validateUploadLimit(snapshot, submission.uploadLimitKiB());
    }
    validatePassword(submission.setPassword(), submission.password());
  }

  private static void validateCurrentSecurityState(
      SecurityLevelsSnapshot securitySnapshot, FirstTimeWizardSubmission submission) {
    SecurityNetworkThreatLevel networkThreatLevel = securitySnapshot.networkThreatLevel();
    SecurityPhysicalThreatLevel physicalThreatLevel = securitySnapshot.physicalThreatLevel();
    if (!supportsWizardNetworkThreatLevel(networkThreatLevel)
        && !submission.preserveCurrentNetworkThreatLevel()) {
      throw new PlatformApiException(
          409,
          "wizard_current_security_unsupported",
          "Current LOW or MAXIMUM network threat levels cannot be represented by the wizard"
              + " controls. Retry with preserveCurrentNetworkThreatLevel=true or use the"
              + " dedicated security controls.");
    }
    if (!supportsWizardPhysicalThreatLevel(physicalThreatLevel)
        && !submission.preserveCurrentPhysicalThreatLevel()) {
      throw new PlatformApiException(
          409,
          "wizard_current_security_unsupported",
          "Current LOW or MAXIMUM physical threat levels cannot be represented by the wizard"
              + " controls. Retry with preserveCurrentPhysicalThreatLevel=true or use the"
              + " dedicated security controls.");
    }
  }

  private static boolean supportsWizardNetworkThreatLevel(SecurityNetworkThreatLevel level) {
    return level == SecurityNetworkThreatLevel.NORMAL || level == SecurityNetworkThreatLevel.HIGH;
  }

  private static boolean supportsWizardPhysicalThreatLevel(SecurityPhysicalThreatLevel level) {
    return level == SecurityPhysicalThreatLevel.NORMAL || level == SecurityPhysicalThreatLevel.HIGH;
  }

  private static void validatePasswordFlowAvailability(
      FirstTimeWizardSnapshot snapshot, FirstTimeWizardSubmission submission) {
    if (snapshot.passwordAlreadySet() && submission.setPassword()) {
      throw new PlatformApiException(
          409,
          "wizard_password_already_set",
          "A startup password is already set. Use the dedicated security/password flow instead"
              + " of the first-time wizard submission.");
    }
    if (submission.preserveCurrentPhysicalThreatLevel() && submission.setPassword()) {
      throw invalidQuery(
          queryParameter(PARAMETER_SET_PASSWORD)
              + " cannot be combined with "
              + queryParameter(PARAMETER_PRESERVE_CURRENT_PHYSICAL_THREAT_LEVEL)
              + ".");
    }
  }

  private static void validateDownloadLimit(
      FirstTimeWizardSnapshot snapshot, String downloadLimitKiB) {
    long parsedDownloadLimitBytes =
        parseSizedLong(
            downloadLimitKiB, "KiB", PARAMETER_DOWNLOAD_LIMIT_KIB, INVALID_KIB_VALUE_MESSAGE);
    if (parsedDownloadLimitBytes > MAX_INT_BACKED_BANDWIDTH_LIMIT_BYTES) {
      throw invalidQuery(
          queryParameter(PARAMETER_DOWNLOAD_LIMIT_KIB)
              + " exceeds the maximum supported bandwidth limit.");
    }
    if (parsedDownloadLimitBytes < snapshot.minBandwidthKiB() * KIB) {
      throw invalidQuery(
          queryParameter(PARAMETER_DOWNLOAD_LIMIT_KIB)
              + MUST_BE_AT_LEAST
              + snapshot.minBandwidthKiB()
              + KIB_UNIT_SUFFIX);
    }
  }

  private static void validateUploadLimit(FirstTimeWizardSnapshot snapshot, String uploadLimitKiB) {
    long parsedUploadLimitBytes =
        parseSizedLong(
            uploadLimitKiB, "KiB", PARAMETER_UPLOAD_LIMIT_KIB, INVALID_KIB_VALUE_MESSAGE);
    if (parsedUploadLimitBytes < snapshot.minBandwidthKiB() * KIB) {
      throw invalidQuery(
          queryParameter(PARAMETER_UPLOAD_LIMIT_KIB)
              + MUST_BE_AT_LEAST
              + snapshot.minBandwidthKiB()
              + KIB_UNIT_SUFFIX);
    }
    if (parsedUploadLimitBytes > snapshot.maxUploadLimitKiB() * KIB) {
      throw invalidQuery(
          queryParameter(PARAMETER_UPLOAD_LIMIT_KIB)
              + MUST_BE_AT_MOST
              + snapshot.maxUploadLimitKiB()
              + KIB_UNIT_SUFFIX);
    }
  }

  private static void validateMonthlyLimit(
      FirstTimeWizardSnapshot snapshot, String bandwidthMonthlyLimitGiB) {
    long requestedMonthlyLimitBytes =
        parseSizedLong(
            bandwidthMonthlyLimitGiB,
            "GiB",
            PARAMETER_BANDWIDTH_MONTHLY_LIMIT_GIB,
            INVALID_GIB_VALUE_MESSAGE);
    long minimumMonthlyLimitBytes =
        parseSizedLong(
            snapshot.minBandwidthMonthlyLimitGiB(),
            "GiB",
            PARAMETER_BANDWIDTH_MONTHLY_LIMIT_GIB,
            INVALID_GIB_VALUE_MESSAGE);
    if (requestedMonthlyLimitBytes < minimumMonthlyLimitBytes) {
      throw invalidQuery(
          queryParameter(PARAMETER_BANDWIDTH_MONTHLY_LIMIT_GIB)
              + MUST_BE_AT_LEAST
              + snapshot.minBandwidthMonthlyLimitGiB()
              + GIB_UNIT_SUFFIX);
    }
  }

  private static void validateStorageLimit(
      FirstTimeWizardSnapshot snapshot, String storageLimitGiB) {
    long requestedStorageLimitBytes =
        parseSizedLong(
            storageLimitGiB, "GiB", PARAMETER_STORAGE_LIMIT_GIB, INVALID_GIB_VALUE_MESSAGE);
    if (requestedStorageLimitBytes < snapshot.minStorageLimitBytes()) {
      throw invalidQuery(
          queryParameter(PARAMETER_STORAGE_LIMIT_GIB)
              + MUST_BE_AT_LEAST
              + snapshot.minStorageLimitGiB()
              + GIB_UNIT_SUFFIX);
    }
    if (requestedStorageLimitBytes > snapshot.maxStorageLimitBytes()) {
      throw invalidQuery(
          queryParameter(PARAMETER_STORAGE_LIMIT_GIB)
              + MUST_BE_AT_MOST
              + snapshot.maxStorageLimitGiB()
              + GIB_UNIT_SUFFIX);
    }
  }

  private static void validatePassword(boolean setPassword, String password) {
    if (!setPassword) {
      return;
    }
    if (password.isEmpty()) {
      throw invalidQuery(
          queryParameter(PARAMETER_PASSWORD) + " must not be empty when setPassword is enabled.");
    }
    if (password.length() > MAX_PASSWORD_LENGTH) {
      throw invalidQuery(
          queryParameter(PARAMETER_PASSWORD)
              + " must not exceed "
              + MAX_PASSWORD_LENGTH
              + " characters.");
    }
  }

  private static long parseSizedLong(
      String value, String suffix, String parameterName, String invalidMessage) {
    try {
      return Fields.parseLong(value + suffix);
    } catch (NumberFormatException _) {
      throw invalidQuery(queryParameter(parameterName) + " " + invalidMessage);
    }
  }

  private static String optionalString(Map<String, List<String>> queryParameters, String name) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, name);
    return value == null ? "" : value;
  }

  private static boolean readCheckboxBoolean(
      Map<String, List<String>> queryParameters, String name) {
    List<String> values = queryParameters.get(name);
    if (values == null || values.isEmpty()) {
      return false;
    }
    boolean anyTruthy = false;
    for (String raw : values) {
      if (raw == null || isTruthyCheckboxValue(raw, name)) {
        anyTruthy = true;
      } else if (!isFalseyCheckboxValue(raw)) {
        throw invalidQuery(
            queryParameter(name)
                + " must be a checkbox value or one of 'true', 'false', 'on', or 'off'.");
      }
    }
    return anyTruthy;
  }

  private static boolean isTruthyCheckboxValue(String raw, String name) {
    return raw.isBlank()
        || "true".equalsIgnoreCase(raw)
        || "on".equalsIgnoreCase(raw)
        || name.equals(raw);
  }

  private static boolean isFalseyCheckboxValue(String raw) {
    return "false".equalsIgnoreCase(raw) || "off".equalsIgnoreCase(raw);
  }

  private static String queryParameter(String name) {
    return "Query parameter '" + name + "'";
  }

  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }
}
