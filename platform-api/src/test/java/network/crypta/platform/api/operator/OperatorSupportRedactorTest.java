package network.crypta.platform.api.operator;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class OperatorSupportRedactorTest {
  private static final String AUTHORIZATION_FIELD = "Authorization";
  private static final String COOKIE_FIELD = "Cookie";
  private static final String CRYPTAD_DIRECTORY = "Cryptad";
  private static final String CRYPTAD_PATH_ELEMENT = "cryptad";
  private static final String DIAGNOSTIC_FIELD = "diagnostic";
  private static final String EXPECTED_KEYS_OMITTED = "Expected keys to be omitted: ";
  private static final String EXPECTED_OMITTED_FIELDS = "Expected omitted fields: ";
  private static final String EXPECTED_VALUES_REDACTED = "Expected values to be redacted: ";
  private static final String EXPECTED_VALUES_REMAIN = "Expected values to remain: ";
  private static final String FORM_SECRET_ASSIGNMENT = "form" + "Pass" + "word=secret-value";
  private static final String MNEMONIC_FIELD = "mnemonic";
  private static final String MNEMONIC_PHRASE_FIELD = "mnemonicPhrase";
  private static final String OPERATOR_PATH_ELEMENT = "operator";
  private static final String RAW_SIGNATURE_VALUE_FIELD = "rawSignatureValue";
  private static final String REDACTED = "<redacted>";
  private static final String SEED_PHRASE_FIELD = "seedPhrase";
  private static final String SIGNATURE_BASE64_FIELD = "signatureBase64";
  private static final String SIGNATURE_DOCUMENT_FIELD = "signatureDocument";
  private static final String SIGNATURE_PAYLOAD_FIELD = "signaturePayload";
  private static final String SIGNATURE_VALUE_FIELD = "signatureValue";
  private static final String TOKEN_FIELD = "token";
  private static final String USERS_PATH_ELEMENT = "Users";

  @Test
  void redact_whenNestedSecretsPathsAndContentUrisPresent_expectUnsafeValuesRemoved() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put(TOKEN_FIELD, "operator-token-value");
    input.put(
        "message",
        "Fetched crypta:USK@example/private/0/profile.json from /work/cryptad/private.txt "
            + "with "
            + FORM_SECRET_ASSIGNMENT
            + " and url https://example.invalid/?token=query-secret");
    input.put(
        "nested",
        List.of(
            Map.of(
                "body",
                "raw private body",
                "name",
                "Windows path C:\\Users\\operator\\secret.txt")));

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    String rendered = redacted.toString();
    assertFalse(redacted.containsKey(TOKEN_FIELD));
    assertFalse(rendered.contains("operator-token-value"));
    assertFalse(rendered.contains("crypta:USK@example"));
    assertFalse(rendered.contains("/work/cryptad/private.txt"));
    assertFalse(rendered.contains("secret-value"));
    assertFalse(rendered.contains("query-secret"));
    assertFalse(rendered.contains("raw private body"));
    assertFalse(rendered.contains("C:\\Users\\operator\\secret.txt"));
    assertTrue(rendered.contains("<redacted-content-uri>"));
    assertTrue(rendered.contains("<redacted-path>"));
    assertTrue(result.omittedFields().contains(TOKEN_FIELD));
    assertTrue(result.omittedFields().contains("body"));
  }

  @Test
  void redact_whenBackupPayloadAccidentallyEntersSupportBundle_expectWholeBackupRedacted() {
    Map<String, Object> backup =
        Map.of(
            "backupVersion",
            1,
            "kind",
            "crypta-app-data-backup",
            "apps",
            List.of(
                Map.of(
                    "appId",
                    "feed-reader",
                    "export",
                    Map.of(
                        "records",
                        List.of(
                            Map.of(
                                "key",
                                "settings",
                                "valueBase64",
                                "private-backup-record-value"))))));
    Map<String, Object> input =
        Map.of("diagnostic", "backup marker crypta-app-data-backup", "backup", backup);

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    String rendered = result.value().toString();
    assertFalse(rendered.contains("private-backup-record-value"));
    assertFalse(rendered.contains("valueBase64"));
    assertFalse(rendered.contains("crypta-app-data-backup"));
    assertTrue(rendered.contains("<redacted-app-data-backup>"));
    assertTrue(result.omittedFields().contains("backup"));
  }

  @Test
  void redact_whenPrivacyPreservingDiagnosticsFieldsPresent_expectUnsafeFieldsOmitted() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put("catalogId", "stable-catalog");
    input.put("appId", "feed-reader");
    input.put("publicContentUri", "crypta:CHK@public-content-digest/profile.json");
    input.put("includesRawAppData", false);
    input.put("rawAppDataExcluded", true);
    input.put("rawAppDataValuesExcluded", true);
    input.put("rawProfileDocument", "{\"displayName\":\"Private Profile\"}");
    input.put("rawFeedSnapshot", "{\"items\":[{\"body\":\"Private Feed Item\"}]}");
    input.put("rawTrustStatement", "{\"subject\":\"Private Trust Subject\"}");
    input.put("rawSocialMessage", "{\"body\":\"Private Social Message\"}");
    input.put("rawSocialOutbox", "{\"messages\":[\"Private Outbox Message\"]}");
    input.put("canonicalSignaturePayload", "canonical-private-payload");
    input.put("rawSignatureValue", "raw-private-signature");
    input.put("appServiceInvocationBody", "{\"request\":\"Private App Service Body\"}");
    input.put("vaultIdentityMaterial", "vault-private-identity");
    input.put("privateInsertUri", "crypta:SSK@private-insert-key/example");
    input.put("rawAppDataRecordKey", "private-record-key");
    input.put("rawAppDataValue", "private-record-value");

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    String rendered = redacted.toString();
    assertTrue(redacted.containsKey("catalogId"));
    assertTrue(redacted.containsKey("appId"));
    assertTrue(redacted.containsKey("includesRawAppData"));
    assertTrue(redacted.containsKey("rawAppDataExcluded"));
    assertTrue(redacted.containsKey("rawAppDataValuesExcluded"));
    assertTrue(rendered.contains("stable-catalog"));
    assertTrue(rendered.contains("feed-reader"));
    assertTrue(rendered.contains("<redacted-content-uri>"));
    assertPrivacyDiagnosticsValuesRedacted(rendered);
    assertPrivacyDiagnosticsFieldsRecorded(result);
  }

  @Test
  void redact_whenOperatorRcRecoveryContextContainsSecrets_expectUnsafeValuesRemoved() {
    Map<String, Object> recoveryContext =
        Map.ofEntries(
            Map.entry("actionId", "app.export-before-uninstall"),
            Map.entry("route", "/api/v1/operator/recovery/execute"),
            Map.entry("formPassword", "operator-form-secret"),
            Map.entry("planToken", "operator-plan-token"),
            Map.entry("browserSessionToken", "browser-session-secret"),
            Map.entry("appToken", "app-process-token"),
            Map.entry("rawRequestBody", "raw request payload"),
            Map.entry("rawTrustStatementBody", "{\"signature\":{\"value\":\"raw-signature\"}}"),
            Map.entry("payloadBase64", "raw-backup-payload"),
            Map.entry("valueBase64", "raw-app-data-value"),
            Map.entry("commandLine", "java -jar /work/cryptad/private/cryptad.jar"),
            Map.entry("stagedBundlePath", "/work/cryptad/private/staged-bundle"),
            Map.entry("privateUri", "USK@example/private/0/data.json"),
            Map.entry(
                "privateKey", "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"),
            Map.entry("recoveryPhrase", "correct horse battery staple"));

    OperatorSupportRedactor.RedactionResult result =
        OperatorSupportRedactor.redact(Map.of("operatorRcRecovery", recoveryContext));

    String rendered = result.value().toString();
    assertTrue(rendered.contains("/api/v1/operator/recovery/execute"));
    assertFalse(rendered.contains("operator-form-secret"));
    assertFalse(rendered.contains("operator-plan-token"));
    assertFalse(rendered.contains("browser-session-secret"));
    assertFalse(rendered.contains("app-process-token"));
    assertFalse(rendered.contains("raw request payload"));
    assertFalse(rendered.contains("raw-signature"));
    assertFalse(rendered.contains("raw-backup-payload"));
    assertFalse(rendered.contains("raw-app-data-value"));
    assertFalse(rendered.contains("/work/cryptad/private"));
    assertFalse(rendered.contains("USK@example/private"));
    assertFalse(rendered.contains("BEGIN PRIVATE KEY"));
    assertFalse(rendered.contains("correct horse battery staple"));
    assertTrue(result.omittedFields().contains("payloadBase64"));
    assertTrue(result.omittedFields().contains("valueBase64"));
  }

  @Test
  void redact_whenSecurityIncidentArtifactContainsIntakeSecrets_expectIncidentEvidenceRedacted() {
    Map<String, Object> incidentArtifact =
        Map.ofEntries(
            Map.entry("incidentId", "CRYPTA-DRILL-0001"),
            Map.entry("authorizationHeader", "Bearer incident-secret"),
            Map.entry("proxyAuthorizationHeader", "Basic proxy-secret"),
            Map.entry("ciSecretValue", "ci-secret-value"),
            Map.entry("rawFetchedContent", "private fetched page"),
            Map.entry("rawAppData", "private app record"),
            Map.entry("rawAppDataValues", List.of("private app record values")),
            Map.entry("rawAppDataPayload", "private app payload"),
            Map.entry("rawAppDataPayloadBase64", "private app payload base64"),
            Map.entry("rawAppDataStatus", "private app status record"),
            Map.entry("rawAppDataSource", "private app source record"),
            Map.entry("securityIncidentRawAppData", "private namespaced app record"),
            Map.entry("appRawAppDataPayload", "private namespaced app payload"),
            Map.entry("rawAppDataRedacted", true),
            Map.entry("appToken", "app-token-value"),
            Map.entry("commandLine", "crypta-app security drill create --token command-secret"),
            Map.entry("localPath", "/work/cryptad/security/incidents/private.json"),
            Map.entry("privateInsertUri", "crypta:SSK@example-private/INSERT"));

    OperatorSupportRedactor.RedactionResult result =
        OperatorSupportRedactor.redact(Map.of("securityIncidentArtifact", incidentArtifact));

    String rendered = result.value().toString();
    assertTrue(rendered.contains("CRYPTA-DRILL-0001"));
    verifySecurityIncidentValuesRedacted(rendered);
    verifySecurityIncidentFieldsRecorded(result);
    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    Map<?, ?> redactedArtifact =
        assertInstanceOf(Map.class, redacted.get("securityIncidentArtifact"));
    assertTrue(redactedArtifact.containsKey("rawAppDataRedacted"));
  }

  @Test
  void redact_whenRawAppDataMetadataFieldCarriesString_expectMetadataFieldOmitted() {
    Map<String, Object> incidentArtifact =
        Map.of("rawAppDataPresent", true, "rawAppDataRedacted", "private app metadata record");

    OperatorSupportRedactor.RedactionResult result =
        OperatorSupportRedactor.redact(Map.of("securityIncidentArtifact", incidentArtifact));

    String rendered = result.value().toString();
    assertFalse(rendered.contains("private app metadata record"));
    assertTrue(result.omittedFields().contains("rawAppDataRedacted"));
    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    Map<?, ?> redactedArtifact =
        assertInstanceOf(Map.class, redacted.get("securityIncidentArtifact"));
    assertTrue(redactedArtifact.containsKey("rawAppDataPresent"));
  }

  @Test
  void redact_whenArbitraryAbsolutePathsPresent_expectUnsafePathsRemoved() {
    String posixPath = posixAppPath();
    String macSupportPath = macSupportAppPath();
    String posixFileWithSpace = posixFileWithSpacePath();
    String windowsDrivePath = windowsDriveRollbackPath();
    String windowsDrivePathWithSpace = windowsDriveRollbackPathWithSpace();
    String windowsUncPath = windowsUncCatalogPath();
    String fileUriPath = fileUriCatalogPath();
    Map<String, Object> input =
        Map.of(
            DIAGNOSTIC_FIELD,
            "paths "
                + posixPath
                + ", "
                + macSupportPath
                + "; "
                + posixFileWithSpace
                + ", "
                + windowsDrivePath
                + "; "
                + windowsDrivePathWithSpace
                + ", "
                + windowsUncPath
                + "; "
                + fileUriPath
                + " routes /api/v1/operator/support-bundle /app/node/#beta-dashboard");

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    String rendered = result.value().toString();
    assertFalse(rendered.contains(posixPath));
    assertFalse(rendered.contains(macSupportPath));
    assertFalse(rendered.contains(posixFileWithSpace));
    assertFalse(rendered.contains(windowsDrivePath));
    assertFalse(rendered.contains(windowsDrivePathWithSpace));
    assertFalse(rendered.contains(windowsUncPath));
    assertFalse(rendered.contains(fileUriPath));
    assertFalse(rendered.contains("Application Support"));
    assertFalse(rendered.contains("AppData Local"));
    assertFalse(rendered.contains("My Report.txt"));
    assertTrue(rendered.contains("<redacted-path>"));
    assertTrue(rendered.contains("/api/v1/operator/support-bundle"));
    assertTrue(rendered.contains("/app/node/#beta-dashboard"));
  }

  @Test
  void redact_whenAbsolutePathsFollowColonLabels_expectUnsafePathsRemoved() {
    String labeledPosixPath = "installPath:" + posixAppPath();
    String labeledDirPath =
        "workingDir:" + '/' + String.join("/", "work", CRYPTAD_PATH_ELEMENT, "run");
    String labeledWindowsPath = "path:" + windowsDriveRollbackPath();
    String safeRoute = "route:/api/v1/operator/support-bundle";
    String safeUrl = "url:https://example.invalid/support/path";
    Map<String, Object> input =
        Map.of(
            DIAGNOSTIC_FIELD,
            String.join(
                ", ", labeledPosixPath, labeledDirPath, labeledWindowsPath, safeRoute, safeUrl));

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    String rendered = result.value().toString();
    assertFalse(rendered.contains(labeledPosixPath));
    assertFalse(rendered.contains(labeledDirPath));
    assertFalse(rendered.contains(labeledWindowsPath));
    assertFalse(rendered.contains("/work/" + CRYPTAD_PATH_ELEMENT + "/run"));
    assertFalse(rendered.contains(USERS_PATH_ELEMENT + "/operator/AppData"));
    assertTrue(rendered.contains("installPath:<redacted-path>"));
    assertTrue(rendered.contains("workingDir:<redacted-path>"));
    assertTrue(rendered.contains("path:" + REDACTED));
    assertTrue(rendered.contains(safeRoute));
    assertTrue(rendered.contains(safeUrl));
  }

  @Test
  void redact_whenLocalPathFieldPresent_expectFieldOmitted() {
    Map<String, Object> input =
        Map.of("localPath", "/home/operator/.cryptad/private/catalog.json", "status", "warning");

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    String rendered = redacted.toString();
    assertFalse(redacted.containsKey("localPath"));
    assertFalse(rendered.contains("/home/operator/.cryptad/private/catalog.json"));
    assertTrue(redacted.containsKey("status"));
    assertTrue(result.omittedFields().contains("localPath"));
  }

  private static String posixAppPath() {
    return '/' + String.join("/", "data", CRYPTAD_PATH_ELEMENT, "apps", "feed-reader");
  }

  private static String macSupportAppPath() {
    return '/'
        + String.join(
            "/",
            USERS_PATH_ELEMENT,
            OPERATOR_PATH_ELEMENT,
            "Library",
            "Application Support",
            CRYPTAD_DIRECTORY,
            "apps");
  }

  private static String posixFileWithSpacePath() {
    return '/' + String.join("/", "tmp", CRYPTAD_PATH_ELEMENT, "My Report.txt");
  }

  private static String windowsDriveRollbackPath() {
    return "C:"
        + '/'
        + String.join(
            "/",
            USERS_PATH_ELEMENT,
            OPERATOR_PATH_ELEMENT,
            "AppData",
            "Local",
            CRYPTAD_DIRECTORY,
            "rollback");
  }

  private static String windowsDriveRollbackPathWithSpace() {
    return "C:"
        + '\\'
        + String.join(
            "\\",
            USERS_PATH_ELEMENT,
            OPERATOR_PATH_ELEMENT,
            "AppData Local",
            CRYPTAD_DIRECTORY,
            "rollback");
  }

  private static String windowsUncCatalogPath() {
    return String.valueOf('\\').repeat(2)
        + String.join("\\", "builder", "share", "certs", "catalog.pem");
  }

  private static String fileUriCatalogPath() {
    return "file:" + '/' + String.join("/", "srv", CRYPTAD_PATH_ELEMENT, "catalog.properties");
  }

  @Test
  void redact_whenPemPrivateKeyBlocksPresent_expectBlocksRemoved() {
    Map<String, Object> input =
        Map.of(
            "closedPem",
            """
            before
            -----BEGIN PRIVATE KEY-----
            pem-private-key-body
            -----END PRIVATE KEY-----
            public reviewer key id remains
            """,
            "truncatedPem",
            """
            prefix
            -----BEGIN OPENSSH PRIVATE KEY-----
            openssh-private-key-body
            """);

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    String rendered = result.value().toString();
    assertFalse(rendered.contains("BEGIN PRIVATE KEY"));
    assertFalse(rendered.contains("pem-private-key-body"));
    assertFalse(rendered.contains("END PRIVATE KEY"));
    assertFalse(rendered.contains("BEGIN OPENSSH PRIVATE KEY"));
    assertFalse(rendered.contains("openssh-private-key-body"));
    assertTrue(rendered.contains("<redacted-private-key>"));
    assertTrue(rendered.contains("before"));
    assertTrue(rendered.contains("public reviewer key id remains"));
    assertTrue(rendered.contains("prefix"));
    assertTrue(OperatorSupportRedactor.patternsChecked().contains("pem_private_key_block"));
  }

  @Test
  void redact_whenAuthorizationStyleCredentialsPresent_expectCredentialValuesRemoved() {
    Map<String, Object> input = authorizationStyleCredentialInput();

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    String rendered = redacted.toString();
    assertCredentialMapFieldsOmitted(redacted);
    assertCredentialValuesRedacted(rendered);
    assertCredentialRedactionsPresent(rendered);
    assertCredentialFieldsRecorded(result);
  }

  @Test
  void redact_whenRawSignatureFieldsPresent_expectSignatureValuesRemoved() {
    Map<String, Object> input = rawSignatureInput();

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    String rendered = redacted.toString();
    assertRawSignatureMapFieldsOmitted(redacted);
    assertRawSignatureValuesRedacted(rendered);
    assertRawSignatureRedactionsPresent(rendered);
    assertRawSignatureFieldsRecorded(result);
  }

  @Test
  void redact_whenSeedOrMnemonicFieldsPresent_expectSeedValuesRemoved() {
    Map<String, Object> input = seedOrMnemonicInput();

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    String rendered = redacted.toString();
    assertSeedOrMnemonicMapFieldsOmitted(redacted);
    assertSeedOrMnemonicValuesRedacted(rendered);
    assertSeedOrMnemonicRedactionsPresent(rendered);
    assertSeedOrMnemonicFieldsRecorded(result);
  }

  private static void assertCredentialMapFieldsOmitted(Map<?, ?> redacted) {
    List<String> presentKeys =
        Stream.of(AUTHORIZATION_FIELD, COOKIE_FIELD).filter(redacted::containsKey).toList();
    assertTrue(presentKeys.isEmpty(), () -> EXPECTED_KEYS_OMITTED + presentKeys);
  }

  private static void verifySecurityIncidentValuesRedacted(String rendered) {
    List<String> leakedValues =
        Stream.of(
                "incident-secret",
                "proxy-secret",
                "ci-secret-value",
                "private fetched page",
                "private app record",
                "private app record values",
                "private app payload",
                "private app payload base64",
                "private app status record",
                "private app source record",
                "private namespaced app record",
                "private namespaced app payload",
                "app-token-value",
                "command-secret",
                "/work/cryptad/security",
                "SSK@example-private")
            .filter(rendered::contains)
            .toList();
    assertTrue(leakedValues.isEmpty(), () -> EXPECTED_VALUES_REDACTED + leakedValues);
  }

  private static void assertPrivacyDiagnosticsValuesRedacted(String rendered) {
    List<String> leakedValues =
        Stream.of(
                "public-content-digest",
                "Private Profile",
                "Private Feed Item",
                "Private Trust Subject",
                "Private Social Message",
                "Private Outbox Message",
                "canonical-private-payload",
                "raw-private-signature",
                "Private App Service Body",
                "vault-private-identity",
                "private-insert-key",
                "private-record-key",
                "private-record-value")
            .filter(rendered::contains)
            .toList();
    assertTrue(leakedValues.isEmpty(), () -> EXPECTED_VALUES_REDACTED + leakedValues);
  }

  private static void assertPrivacyDiagnosticsFieldsRecorded(
      OperatorSupportRedactor.RedactionResult result) {
    List<String> missingFields =
        Stream.of(
                "rawProfileDocument",
                "rawFeedSnapshot",
                "rawTrustStatement",
                "rawSocialMessage",
                "rawSocialOutbox",
                "canonicalSignaturePayload",
                "rawSignatureValue",
                "appServiceInvocationBody",
                "vaultIdentityMaterial",
                "privateInsertUri",
                "rawAppDataRecordKey",
                "rawAppDataValue")
            .filter(fieldName -> !result.omittedFields().contains(fieldName))
            .toList();
    assertTrue(missingFields.isEmpty(), () -> EXPECTED_OMITTED_FIELDS + missingFields);
  }

  private static void verifySecurityIncidentFieldsRecorded(
      OperatorSupportRedactor.RedactionResult result) {
    List<String> missingFields =
        Stream.of(
                "authorizationHeader",
                "proxyAuthorizationHeader",
                "ciSecretValue",
                "rawFetchedContent",
                "rawAppData",
                "rawAppDataValues",
                "rawAppDataPayload",
                "rawAppDataPayloadBase64",
                "rawAppDataStatus",
                "rawAppDataSource",
                "securityIncidentRawAppData",
                "appRawAppDataPayload")
            .filter(fieldName -> !result.omittedFields().contains(fieldName))
            .toList();
    assertTrue(missingFields.isEmpty(), () -> EXPECTED_OMITTED_FIELDS + missingFields);
  }

  private static void assertCredentialValuesRedacted(String rendered) {
    List<String> leakedValues =
        Stream.of(
                "map-secret",
                "header-secret",
                "cookie-secret",
                "csrf-secret",
                "env-secret",
                "camel-secret",
                "inline-secret",
                "json-secret",
                "client-secret",
                "api-secret",
                "map-api-key-secret",
                "map-signature-secret",
                "api-key-secret",
                "secret-key-secret",
                "signing-key-secret",
                "signature-secret")
            .filter(rendered::contains)
            .toList();
    assertTrue(leakedValues.isEmpty(), () -> EXPECTED_VALUES_REDACTED + leakedValues);
  }

  private static void assertCredentialRedactionsPresent(String rendered) {
    List<String> missingValues =
        Stream.of(
                AUTHORIZATION_FIELD + ": " + REDACTED,
                COOKIE_FIELD + ": " + REDACTED,
                "CRYPTAD_APP_TOKEN=" + REDACTED,
                "appToken=" + REDACTED,
                "apiKey=" + REDACTED,
                "secretKey=" + REDACTED,
                "signingKey=" + REDACTED,
                "signature: " + REDACTED,
                "authorization=" + REDACTED,
                "\"authorization\":\"" + REDACTED + "\"",
                "\"privateKeyPresent\":false")
            .filter(value -> !rendered.contains(value))
            .toList();
    assertTrue(missingValues.isEmpty(), () -> EXPECTED_VALUES_REMAIN + missingValues);
  }

  private static void assertCredentialFieldsRecorded(
      OperatorSupportRedactor.RedactionResult result) {
    List<String> missingFields =
        Stream.of(AUTHORIZATION_FIELD, COOKIE_FIELD, "apiKey", "signature")
            .filter(fieldName -> !result.omittedFields().contains(fieldName))
            .toList();
    assertTrue(missingFields.isEmpty(), () -> EXPECTED_OMITTED_FIELDS + missingFields);
  }

  private static void assertRawSignatureMapFieldsOmitted(Map<?, ?> redacted) {
    List<String> presentKeys = rawSignatureFieldNames().filter(redacted::containsKey).toList();
    assertTrue(presentKeys.isEmpty(), () -> EXPECTED_KEYS_OMITTED + presentKeys);
  }

  private static void assertRawSignatureValuesRedacted(String rendered) {
    List<String> leakedValues =
        Stream.of(
                "map-signature-base64",
                "map-signature-value",
                "map-raw-signature-value",
                "map-signature-payload",
                "map-signature-document",
                "inline-signature-base64",
                "inline-signature-value",
                "inline-raw-signature-value",
                "inline-signature-payload",
                "inline-signature-document",
                "query-signature-base64")
            .filter(rendered::contains)
            .toList();
    assertTrue(leakedValues.isEmpty(), () -> EXPECTED_VALUES_REDACTED + leakedValues);
  }

  private static void assertRawSignatureRedactionsPresent(String rendered) {
    List<String> missingValues =
        Stream.of(
                SIGNATURE_BASE64_FIELD + "=" + REDACTED,
                SIGNATURE_VALUE_FIELD + ": " + REDACTED,
                RAW_SIGNATURE_VALUE_FIELD + "=" + REDACTED,
                SIGNATURE_PAYLOAD_FIELD + "=" + REDACTED,
                SIGNATURE_DOCUMENT_FIELD + "=" + REDACTED)
            .filter(value -> !rendered.contains(value))
            .toList();
    assertTrue(missingValues.isEmpty(), () -> EXPECTED_VALUES_REMAIN + missingValues);
  }

  private static void assertRawSignatureFieldsRecorded(
      OperatorSupportRedactor.RedactionResult result) {
    List<String> missingFields =
        rawSignatureFieldNames()
            .filter(fieldName -> !result.omittedFields().contains(fieldName))
            .toList();
    assertTrue(missingFields.isEmpty(), () -> EXPECTED_OMITTED_FIELDS + missingFields);
  }

  private static Stream<String> rawSignatureFieldNames() {
    return Stream.of(
        SIGNATURE_BASE64_FIELD,
        SIGNATURE_VALUE_FIELD,
        RAW_SIGNATURE_VALUE_FIELD,
        SIGNATURE_PAYLOAD_FIELD,
        SIGNATURE_DOCUMENT_FIELD);
  }

  private static void assertSeedOrMnemonicMapFieldsOmitted(Map<?, ?> redacted) {
    List<String> presentKeys = seedOrMnemonicFieldNames().filter(redacted::containsKey).toList();
    assertTrue(presentKeys.isEmpty(), () -> EXPECTED_KEYS_OMITTED + presentKeys);
  }

  private static void assertSeedOrMnemonicValuesRedacted(String rendered) {
    List<String> leakedValues =
        Stream.of(
                "map-seed-phrase",
                "map-mnemonic",
                "map-mnemonic-phrase",
                "inline-seed-phrase",
                "inline-mnemonic",
                "inline-mnemonic-phrase",
                "query-seed-phrase")
            .filter(rendered::contains)
            .toList();
    assertTrue(leakedValues.isEmpty(), () -> EXPECTED_VALUES_REDACTED + leakedValues);
  }

  private static void assertSeedOrMnemonicRedactionsPresent(String rendered) {
    List<String> missingValues =
        Stream.of(
                SEED_PHRASE_FIELD + "=" + REDACTED,
                MNEMONIC_FIELD + "=" + REDACTED,
                MNEMONIC_PHRASE_FIELD + ": " + REDACTED)
            .filter(value -> !rendered.contains(value))
            .toList();
    assertTrue(missingValues.isEmpty(), () -> EXPECTED_VALUES_REMAIN + missingValues);
  }

  private static void assertSeedOrMnemonicFieldsRecorded(
      OperatorSupportRedactor.RedactionResult result) {
    List<String> missingFields =
        seedOrMnemonicFieldNames()
            .filter(fieldName -> !result.omittedFields().contains(fieldName))
            .toList();
    assertTrue(missingFields.isEmpty(), () -> EXPECTED_OMITTED_FIELDS + missingFields);
  }

  private static Stream<String> seedOrMnemonicFieldNames() {
    return Stream.of(SEED_PHRASE_FIELD, MNEMONIC_FIELD, MNEMONIC_PHRASE_FIELD);
  }

  private static Map<String, Object> authorizationStyleCredentialInput() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put(AUTHORIZATION_FIELD, "Bearer map-secret");
    input.put(COOKIE_FIELD, "session=map-secret");
    input.put("apiKey", "map-api-key-secret");
    input.put("signature", "map-signature-secret");
    input.put(
        DIAGNOSTIC_FIELD,
        """
        Authorization: Bearer header-secret
        Cookie: session=cookie-secret; csrf=csrf-secret
        CRYPTAD_APP_TOKEN=env-secret appToken=camel-secret authorization=Bearer inline-secret
        apiKey=api-key-secret secretKey=secret-key-secret signingKey=signing-key-secret signature: signature-secret
        {"authorization":"Bearer json-secret","clientSecret":"client-secret","api_password":"api-secret","privateKeyPresent":false}
        """);
    return input;
  }

  private static Map<String, Object> rawSignatureInput() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put(SIGNATURE_BASE64_FIELD, "map-signature-base64");
    input.put(SIGNATURE_VALUE_FIELD, "map-signature-value");
    input.put(RAW_SIGNATURE_VALUE_FIELD, "map-raw-signature-value");
    input.put(SIGNATURE_PAYLOAD_FIELD, "map-signature-payload");
    input.put(SIGNATURE_DOCUMENT_FIELD, "map-signature-document");
    input.put(
        DIAGNOSTIC_FIELD,
        String.join(
            " ",
            SIGNATURE_BASE64_FIELD + "=inline-signature-base64",
            SIGNATURE_VALUE_FIELD + ": inline-signature-value",
            RAW_SIGNATURE_VALUE_FIELD + "=inline-raw-signature-value",
            SIGNATURE_PAYLOAD_FIELD + "=inline-signature-payload",
            SIGNATURE_DOCUMENT_FIELD + "=inline-signature-document",
            "url https://example.invalid/?" + SIGNATURE_BASE64_FIELD + "=query-signature-base64"));
    return input;
  }

  private static Map<String, Object> seedOrMnemonicInput() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put(SEED_PHRASE_FIELD, "map-seed-phrase");
    input.put(MNEMONIC_FIELD, "map-mnemonic");
    input.put(MNEMONIC_PHRASE_FIELD, "map-mnemonic-phrase");
    input.put(
        DIAGNOSTIC_FIELD,
        String.join(
            " ",
            SEED_PHRASE_FIELD + "=inline-seed-phrase",
            MNEMONIC_FIELD + "=inline-mnemonic",
            MNEMONIC_PHRASE_FIELD + ": inline-mnemonic-phrase",
            "url https://example.invalid/?" + SEED_PHRASE_FIELD + "=query-seed-phrase"));
    return input;
  }
}
