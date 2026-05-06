package network.crypta.platform.devtools;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class StaticCssInspectorTest {
  @Test
  void inspect_whenRemoteImportPresent_expectError() {
    List<AppUiLintFinding> findings =
        StaticCssInspector.inspect(
            "@IMPORT url('https://cdn.example.invalid/reset.css');", "static/app.css", false);

    assertEquals(1, findings.size());
    assertEquals("remote-css-import", findings.getFirst().id());
    assertEquals("csp", findings.getFirst().category());
    assertEquals(AppUiLintSeverity.ERROR, findings.getFirst().severity());
    assertEquals("static/app.css", findings.getFirst().path());
  }

  @Test
  void inspect_whenLocalImportIsNotNormalized_expectStrictSeverityControlsFindingSeverity() {
    String css =
        """
        @import './tokens.css';
        @import url("../theme.css");
        @import url(local.css);
        """;

    List<AppUiLintFinding> advisoryFindings =
        StaticCssInspector.inspect(css, "static/app.css", false);
    List<AppUiLintFinding> strictFindings = StaticCssInspector.inspect(css, "static/app.css", true);

    assertEquals(
        List.of("css-import-not-normalized", "css-import-not-normalized"),
        advisoryFindings.stream().map(AppUiLintFinding::id).toList());
    assertEquals(
        List.of(AppUiLintSeverity.WARNING, AppUiLintSeverity.WARNING),
        advisoryFindings.stream().map(AppUiLintFinding::severity).toList());
    assertEquals(
        List.of(AppUiLintSeverity.ERROR, AppUiLintSeverity.ERROR),
        strictFindings.stream().map(AppUiLintFinding::severity).toList());
  }

  @Test
  void inspect_whenMalformedImportContainsLongWhitespace_expectNoFinding() {
    String css = "@import " + " ".repeat(50_000) + ";";

    List<AppUiLintFinding> findings = StaticCssInspector.inspect(css, "static/app.css", true);

    assertEquals(List.of(), findings);
  }
}
