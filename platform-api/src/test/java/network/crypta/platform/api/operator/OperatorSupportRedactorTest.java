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
  @Test
  void redact_whenNestedSecretsPathsAndContentUrisPresent_expectUnsafeValuesRemoved() {
    LinkedHashMap<String, Object> input = new LinkedHashMap<>();
    input.put("token", "operator-token-value");
    input.put(
        "message",
        "Fetched crypta:USK@example/private/0/profile.json from /work/cryptad/private.txt "
            + "with formPassword=secret-value and url https://example.invalid/?token=query-secret");
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
    assertFalse(redacted.containsKey("token"));
    assertFalse(rendered.contains("operator-token-value"));
    assertFalse(rendered.contains("crypta:USK@example"));
    assertFalse(rendered.contains("/work/cryptad/private.txt"));
    assertFalse(rendered.contains("secret-value"));
    assertFalse(rendered.contains("query-secret"));
    assertFalse(rendered.contains("raw private body"));
    assertFalse(rendered.contains("C:\\Users\\operator\\secret.txt"));
    assertTrue(rendered.contains("<redacted-content-uri>"));
    assertTrue(rendered.contains("<redacted-path>"));
    assertTrue(result.omittedFields().contains("token"));
    assertTrue(result.omittedFields().contains("body"));
  }
}
