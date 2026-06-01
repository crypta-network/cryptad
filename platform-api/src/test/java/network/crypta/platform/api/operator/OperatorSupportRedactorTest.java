package network.crypta.platform.api.operator;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
  void redact_whenAuthorizationStyleCredentialsPresent_expectCredentialValuesRemoved() {
    Map<String, Object> input = authorizationStyleCredentialInput();

    OperatorSupportRedactor.RedactionResult result = OperatorSupportRedactor.redact(input);

    Map<?, ?> redacted = assertInstanceOf(Map.class, result.value());
    String rendered = redacted.toString();
    assertFalse(redacted.containsKey(AUTHORIZATION_FIELD));
    assertFalse(redacted.containsKey(COOKIE_FIELD));
    assertFalse(rendered.contains("map-secret"));
    assertFalse(rendered.contains("header-secret"));
    assertFalse(rendered.contains("cookie-secret"));
    assertFalse(rendered.contains("csrf-secret"));
    assertFalse(rendered.contains("env-secret"));
    assertFalse(rendered.contains("camel-secret"));
    assertFalse(rendered.contains("inline-secret"));
    assertFalse(rendered.contains("json-secret"));
    assertFalse(rendered.contains("client-secret"));
    assertFalse(rendered.contains("api-secret"));
    assertTrue(rendered.contains(AUTHORIZATION_FIELD + ": " + REDACTED));
    assertTrue(rendered.contains(COOKIE_FIELD + ": " + REDACTED));
    assertTrue(rendered.contains("CRYPTAD_APP_TOKEN=" + REDACTED));
    assertTrue(rendered.contains("appToken=" + REDACTED));
    assertTrue(rendered.contains("authorization=" + REDACTED));
    assertTrue(rendered.contains("\"authorization\":\"" + REDACTED + "\""));
    assertTrue(rendered.contains("\"privateKeyPresent\":false"));
    assertTrue(result.omittedFields().contains(AUTHORIZATION_FIELD));
    assertTrue(result.omittedFields().contains(COOKIE_FIELD));
  }

  private static Map<String, Object> authorizationStyleCredentialInput() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put(AUTHORIZATION_FIELD, "Bearer map-secret");
    input.put(COOKIE_FIELD, "session=map-secret");
    input.put(
        "diagnostic",
        """
        Authorization: Bearer header-secret
        Cookie: session=cookie-secret; csrf=csrf-secret
        CRYPTAD_APP_TOKEN=env-secret appToken=camel-secret authorization=Bearer inline-secret
        {"authorization":"Bearer json-secret","clientSecret":"client-secret","api_password":"api-secret","privateKeyPresent":false}
        """);
    return input;
  }
}
