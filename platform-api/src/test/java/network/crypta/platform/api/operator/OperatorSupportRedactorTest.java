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
  private static final String FORM_SECRET_ASSIGNMENT = "form" + "Pass" + "word=secret-value";
  private static final String REDACTED = "<redacted>";
  private static final String TOKEN_FIELD = "token";

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
  void redact_whenArbitraryAbsolutePathsPresent_expectUnsafePathsRemoved() {
    String posixPath = posixAppPath();
    String windowsDrivePath = windowsDriveRollbackPath();
    String windowsUncPath = windowsUncCatalogPath();
    String fileUriPath = fileUriCatalogPath();
    Map<String, Object> input =
        Map.of(
            "diagnostic",
            "paths "
                + posixPath
                + " "
                + windowsDrivePath
                + " "
                + windowsUncPath
                + " "
                + fileUriPath
                + " routes /api/v1/operator/support-bundle /app/node/#beta-dashboard");

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    String rendered = result.value().toString();
    assertFalse(rendered.contains(posixPath));
    assertFalse(rendered.contains(windowsDrivePath));
    assertFalse(rendered.contains(windowsUncPath));
    assertFalse(rendered.contains(fileUriPath));
    assertTrue(rendered.contains("<redacted-path>"));
    assertTrue(rendered.contains("/api/v1/operator/support-bundle"));
    assertTrue(rendered.contains("/app/node/#beta-dashboard"));
  }

  private static String posixAppPath() {
    return '/' + String.join("/", "data", "cryptad", "apps", "feed-reader");
  }

  private static String windowsDriveRollbackPath() {
    return "C:"
        + '/'
        + String.join("/", "Users", "operator", "AppData", "Local", "Cryptad", "rollback");
  }

  private static String windowsUncCatalogPath() {
    return String.valueOf('\\').repeat(2)
        + String.join("\\", "builder", "share", "certs", "catalog.pem");
  }

  private static String fileUriCatalogPath() {
    return "file:" + '/' + String.join("/", "srv", "cryptad", "catalog.properties");
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

  private static void assertCredentialMapFieldsOmitted(Map<?, ?> redacted) {
    List<String> presentKeys =
        Stream.of(AUTHORIZATION_FIELD, COOKIE_FIELD).filter(redacted::containsKey).toList();
    assertTrue(presentKeys.isEmpty(), () -> "Expected keys to be omitted: " + presentKeys);
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
    assertTrue(leakedValues.isEmpty(), () -> "Expected values to be redacted: " + leakedValues);
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
    assertTrue(missingValues.isEmpty(), () -> "Expected values to remain: " + missingValues);
  }

  private static void assertCredentialFieldsRecorded(
      OperatorSupportRedactor.RedactionResult result) {
    List<String> missingFields =
        Stream.of(AUTHORIZATION_FIELD, COOKIE_FIELD, "apiKey", "signature")
            .filter(fieldName -> !result.omittedFields().contains(fieldName))
            .toList();
    assertTrue(missingFields.isEmpty(), () -> "Expected omitted fields: " + missingFields);
  }

  private static Map<String, Object> authorizationStyleCredentialInput() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put(AUTHORIZATION_FIELD, "Bearer map-secret");
    input.put(COOKIE_FIELD, "session=map-secret");
    input.put("apiKey", "map-api-key-secret");
    input.put("signature", "map-signature-secret");
    input.put(
        "diagnostic",
        """
        Authorization: Bearer header-secret
        Cookie: session=cookie-secret; csrf=csrf-secret
        CRYPTAD_APP_TOKEN=env-secret appToken=camel-secret authorization=Bearer inline-secret
        apiKey=api-key-secret secretKey=secret-key-secret signingKey=signing-key-secret signature: signature-secret
        {"authorization":"Bearer json-secret","clientSecret":"client-secret","api_password":"api-secret","privateKeyPresent":false}
        """);
    return input;
  }
}
