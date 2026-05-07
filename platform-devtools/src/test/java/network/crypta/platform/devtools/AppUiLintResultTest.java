package network.crypta.platform.devtools;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppUiLintResultTest {
  @Test
  void toJson_whenFindingsContainSpecialCharacters_expectEscapedDeterministicOutput() {
    AppUiLintResult result =
        new AppUiLintResult(
            "sample\"app",
            "static",
            true,
            List.of(
                new AppUiLintFinding(
                    "remote-script",
                    "csp",
                    AppUiLintSeverity.ERROR,
                    "quoted \"value\"\nbackslash \\ tab\tcontrol " + '\u001f',
                    "static/index.html"),
                new AppUiLintFinding(
                    "design-system-css-order",
                    "design-system",
                    AppUiLintSeverity.WARNING,
                    "Load local CSS first.",
                    "static/app.css"),
                new AppUiLintFinding(
                    "ui-not-applicable",
                    "ui",
                    AppUiLintSeverity.NOTE,
                    "Only static UI is checked.",
                    "")));

    String json = result.toJson();

    assertTrue(result.hasErrors());
    assertEquals(1, result.errorCount());
    assertEquals(1, result.warningCount());
    assertEquals(1, result.noteCount());
    assertTrue(json.contains("\"appId\": \"sample\\\"app\""));
    assertTrue(json.contains("\"errors\": 1"));
    assertTrue(json.contains("\"warnings\": 1"));
    assertTrue(json.contains("\"notes\": 1"));
    assertTrue(json.contains("quoted \\\"value\\\"\\nbackslash \\\\ tab\\tcontrol \\u001f"));
    assertTrue(json.endsWith("}\n"));
  }
}
