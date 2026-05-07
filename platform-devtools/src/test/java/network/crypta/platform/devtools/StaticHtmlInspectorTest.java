package network.crypta.platform.devtools;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
  void normalizedReferences_whenReferenceContainsRouteInvalidCharacters_expectLintablePaths() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <link rel="stylesheet" href="foo:bar.css">
            <link rel="stylesheet" href="data:text/css,body{}">
            <script src="main:debug.js"></script>
            """,
            "static/index.html",
            Path.of("static"));

    assertEquals(
        List.of("static/foo:bar.css", "static/data:text/css,body{}"),
        inspector.normalizedStylesheetHrefs());
    assertEquals(List.of("static/main:debug.js"), inspector.normalizedScriptSources());
  }

  @Test
  void usesDesignSystemClass_whenDocumentedClassAppearsInClassAttribute_expectTrue() {
    for (String className :
        List.of(
            "cr-permission-summary",
            "cr-label",
            "cr-checkbox",
            "cr-kv-list",
            "cr-kv-row",
            "cr-sr-only",
            "cr-button--primary",
            "cr-status--warning")) {
      StaticHtmlInspector inspector =
          StaticHtmlInspector.inspect(
              "<section class=\"" + className + "\"></section>",
              "static/index.html",
              Path.of("static"));

      assertTrue(inspector.usesDesignSystemClass(), className);
    }
  }

  @Test
  void usesDesignSystemClass_whenCrTextAppearsOutsideClassAttribute_expectFalse() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <p>Use cr-permission-summary here.</p>
            <section data-example="cr-label"></section>
            """,
            "static/index.html",
            Path.of("static"));

    assertFalse(inspector.usesDesignSystemClass());
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
  void sdkFindings_whenSdkIsDeferredBeforeParserBlockingAppScript_expectStrictOrderError() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <script src="../static/crypta-platform.js" defer></script>
            <script src="./main.js"></script>
            """,
            "ui/index.html",
            Path.of("ui"));

    List<AppUiLintFinding> findings = inspector.sdkFindings(true);

    assertEquals(1, findings.size());
    assertEquals("sdk-script-defer-order", findings.getFirst().id());
    assertEquals(AppUiLintSeverity.ERROR, findings.getFirst().severity());
  }

  @Test
  void sdkFindings_whenSdkIsAsyncBeforeDeferredAppScript_expectStrictAsyncError() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <script src="../static/crypta-platform.js" async></script>
            <script src="./main.js" defer></script>
            """,
            "ui/index.html",
            Path.of("ui"));

    List<AppUiLintFinding> findings = inspector.sdkFindings(true);

    assertEquals(1, findings.size());
    assertEquals("sdk-script-async", findings.getFirst().id());
    assertEquals(AppUiLintSeverity.ERROR, findings.getFirst().severity());
  }

  @Test
  void sdkFindings_whenSdkAndAppScriptsAreDeferredInOrder_expectNoFindings() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <script src="../static/crypta-platform.js" defer></script>
            <script src="./main.js" defer></script>
            """,
            "ui/index.html",
            Path.of("ui"));

    assertTrue(inspector.sdkFindings(true).isEmpty());
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
  void accessibilityFindings_whenEssentialsAndAccessibleNamesPresent_expectNoFindings() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <html lang="en">
              <head>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Accessible app</title>
                <style>:focus-visible { outline: 2px solid currentColor; }</style>
              </head>
              <body>
                <h1>Accessible app</h1>
                <label for="named">Name</label>
                <input id="named">
                <label>Filter <input id="wrapped"></label>
                <input type="hidden" id="internal">
                <button aria-label="Refresh"><span></span></button>
                <button title="Open"><span></span></button>
              </body>
            </html>
            """,
            "static/index.html",
            Path.of("static"));

    assertEquals(List.of(), inspector.accessibilityFindings(true, false));
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
  void safetyFindings_whenUrlSchemesUseCharacterReferences_expectCspFindings() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <html lang="en">
              <head>
                <link rel="stylesheet" href="https&#58;//cdn.example.invalid/app.css">
              </head>
              <body>
                <a href="javascript&#58;alert(1)">Bad URL</a>
                <script src="https&colon;&sol;&sol;cdn.example.invalid/app.js"></script>
              </body>
            </html>
            """,
            "static/index.html",
            Path.of("static"));

    Set<String> findingIds = ids(inspector.safetyFindings());

    assertTrue(findingIds.contains("remote-stylesheet"));
    assertTrue(findingIds.contains("javascript-url"));
    assertTrue(findingIds.contains("remote-script"));
  }

  @Test
  void safetyFindings_whenUrlSchemesUseSemicolonlessNumericReferences_expectCspFindings() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <html lang="en">
              <head>
                <link rel="stylesheet" href="https&#58//cdn.example.invalid/app.css">
              </head>
              <body>
                <a href="javascript&#58alert(1)">Bad URL</a>
                <script src="https&#x3A//cdn.example.invalid/app.js"></script>
              </body>
            </html>
            """,
            "static/index.html",
            Path.of("static"));

    Set<String> findingIds = ids(inspector.safetyFindings());

    assertTrue(findingIds.contains("remote-stylesheet"));
    assertTrue(findingIds.contains("javascript-url"));
    assertTrue(findingIds.contains("remote-script"));
  }

  @Test
  void safetyFindings_whenUrlAttributesAreDuplicated_expectFirstAttributeUsed() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <html lang="en">
              <head>
                <link rel="stylesheet" href="https://cdn.example.invalid/app.css" href="./app.css">
              </head>
              <body>
                <a href="javascript:alert(1)" href="./safe.html">Bad URL</a>
                <script src="https://cdn.example.invalid/app.js" src="./app.js"></script>
              </body>
            </html>
            """,
            "static/index.html",
            Path.of("static"));

    Set<String> findingIds = ids(inspector.safetyFindings());

    assertTrue(findingIds.contains("remote-stylesheet"));
    assertTrue(findingIds.contains("javascript-url"));
    assertTrue(findingIds.contains("remote-script"));
  }

  @Test
  void safetyFindings_whenDangerousMarkupAppearsOnlyInComments_expectNoFindings() {
    StaticHtmlInspector inspector =
        StaticHtmlInspector.inspect(
            """
            <html lang="en">
              <head>
                <!-- <base href="https://example.invalid/"> -->
                <!-- <link rel="stylesheet" href="https://cdn.example.invalid/app.css"> -->
              </head>
              <body>
                <!-- <script src="https://cdn.example.invalid/app.js"></script> -->
                <!-- <script>window.inline = true;</script> -->
                <!-- <button onclick="void 0">Bad example</button> -->
                <script src="./app.js"></script>
              </body>
            </html>
            """,
            "static/index.html",
            Path.of("static"));

    assertEquals(Set.of(), ids(inspector.safetyFindings()));
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

  @Test
  void permissionDisclosure_whenAlternateMarkersPresent_expectDetectedPermissions() {
    StaticHtmlInspector dataAttributeInspector =
        StaticHtmlInspector.inspect(
            """
            <section data-crypta-permission-summary>
              <p><code>queue.read</code></p>
            </section>
            """,
            "static/index.html",
            Path.of("static"));
    StaticHtmlInspector customElementInspector =
        StaticHtmlInspector.inspect(
            """
            <crypta-permission-summary>
              <code>content.insert</code>
            </crypta-permission-summary>
            """,
            "static/index.html",
            Path.of("static"));

    assertTrue(dataAttributeInspector.hasPermissionDisclosure());
    assertEquals(
        new LinkedHashSet<>(List.of("queue.read")),
        dataAttributeInspector.mentionedPermissionsInDisclosure());
    assertTrue(customElementInspector.hasPermissionDisclosure());
    assertEquals(
        new LinkedHashSet<>(List.of("content.insert")),
        customElementInspector.mentionedPermissionsInDisclosure());
  }

  private static Set<String> ids(List<AppUiLintFinding> findings) {
    return findings.stream().map(AppUiLintFinding::id).collect(java.util.stream.Collectors.toSet());
  }
}
