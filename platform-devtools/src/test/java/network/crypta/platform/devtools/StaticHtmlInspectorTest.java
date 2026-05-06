package network.crypta.platform.devtools;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class StaticHtmlInspectorTest {
  @Test
  void normalizedReferences_whenEntryIsSubdirectory_expectBundleRelativePaths() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <link rel="stylesheet" href="../static/crypta-ui/crypta-ui.css?version=1">
            <link rel="stylesheet" href="./app.css#screen">
            <script src="../static/crypta-platform.js"></script>
            <script type="module" src="./main.js?version=1#boot"></script>
            """,
            "ui/index.html",
            Path.of("ui"));

    assertEquals(
        List.of("static/crypta-ui/crypta-ui.css", "ui/app.css"),
        inspector.normalizedStylesheetHrefs());
    assertEquals(
        List.of("static/crypta-platform.js", "ui/main.js"), inspector.normalizedScriptSources());
  }

  @Test
  void sdkFindings_whenLocalAppScriptPrecedesSdk_expectStrictOrderError() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <script type="module" src="./main.js"></script>
            <script src="../static/crypta-platform.js"></script>
            """,
            "ui/index.html",
            Path.of("ui"));

    List<AppUiLintFinding> findings = inspector.sdkFindings(true);

    assertEquals(1, findings.size());
    assertEquals("sdk-script-order", findings.getFirst().id());
    assertEquals(AppUiLintSeverity.ERROR, findings.getFirst().severity());
    assertEquals("ui/index.html", findings.getFirst().path());
  }

  @Test
  void accessibilityFindings_whenEssentialsAreMissing_expectStrictErrors() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <html>
              <head></head>
              <body>
                <input id="name">
                <button><span></span></button>
              </body>
            </html>
            """,
            "static/index.html",
            Path.of("static"));

    Set<String> findingIds = ids(inspector.accessibilityFindings(true, false));

    assertEquals(
        Set.of(
            "html-lang-missing",
            "viewport-meta-missing",
            "title-missing",
            "heading-missing",
            "input-label-missing",
            "button-name-missing",
            "focus-visible-style-missing"),
        findingIds);
  }

  @Test
  void safetyFindings_whenDangerousMarkupPresent_expectCspErrorsAndWarnings() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <html lang="en">
              <head>
                <base href="./">
                <link rel="stylesheet" href="https://cdn.example.invalid/app.css">
              </head>
              <body>
                <a href="javascript:alert(1)">Bad URL</a>
                <a href="https://example.invalid">Remote link</a>
                <img src="//example.invalid/pixel.png" alt="">
                <object data="./widget.bin"></object>
                <embed src="./widget.bin">
                <iframe src="https://example.invalid/frame"></iframe>
                <button style="color: red" onclick="void 0">Click</button>
                <script>window.inline = true;</script>
              </body>
            </html>
            """,
            "static/index.html",
            Path.of("static"));

    Set<String> findingIds = ids(inspector.safetyFindings());

    assertTrue(findingIds.contains("base-tag"));
    assertTrue(findingIds.contains("remote-stylesheet"));
    assertTrue(findingIds.contains("javascript-url"));
    assertTrue(findingIds.contains("remote-passive-resource"));
    assertTrue(findingIds.contains("object-embed-tag"));
    assertTrue(findingIds.contains("remote-iframe"));
    assertTrue(findingIds.contains("inline-style"));
    assertTrue(findingIds.contains("inline-event-handler"));
    assertTrue(findingIds.contains("inline-script"));
  }

  @Test
  void mentionedPermissionsInDisclosure_whenDisclosureContainsPermissions_expectStableSet() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <section class="cr-permission-summary">
              <code>queue.read</code>
              <code>publisher.write</code>
            </section>
            """,
            "static/index.html",
            Path.of("static"));

    assertEquals(
        new LinkedHashSet<>(List.of("queue.read", "publisher.write")),
        inspector.mentionedPermissionsInDisclosure());
  }

  private static Set<String> ids(List<AppUiLintFinding> findings) {
    return findings.stream().map(AppUiLintFinding::id).collect(java.util.stream.Collectors.toSet());
  }
}
