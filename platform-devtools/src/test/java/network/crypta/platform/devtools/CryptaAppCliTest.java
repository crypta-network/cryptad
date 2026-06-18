package network.crypta.platform.devtools;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.api.PlatformApiContract;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaAppCliTest {
  private static final String SUBMISSION_METADATA_ENTRY = "crypta-app-submission.json";
  private static final String SUBMISSION_BUNDLE_ARTIFACT_ENTRY = "artifacts/app-bundle.zip";

  @TempDir private Path tempDir;

  @Test
  void init_whenStaticAppRequested_expectStandaloneBundleSkeleton() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(Files.isRegularFile(appDir.resolve("cryptad-app.properties")));
    assertTrue(Files.isRegularFile(appDir.resolve("bin").resolve("start.sh")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("index.html")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("app.js")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("app.css")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("crypta-platform.js")));
    assertTrue(
        Files.isRegularFile(
            appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui-tokens.css")));
    assertTrue(
        Files.isRegularFile(
            appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui.css")));
    assertTrue(
        Files.isRegularFile(
            appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui-components.js")));
    assertTrue(Files.isRegularFile(appDir.resolve("README.md")));
    assertTrue(result.out().contains("Initialized app bundle"));
    String indexHtml = Files.readString(appDir.resolve("static").resolve("index.html"));
    assertTrue(indexHtml.indexOf("crypta-ui-tokens.css") < indexHtml.indexOf("crypta-ui.css"));
    assertTrue(indexHtml.indexOf("crypta-ui.css") < indexHtml.indexOf("app.css"));
    assertTrue(indexHtml.contains("class=\"cr-app\""));
    assertTrue(
        Files.readString(appDir.resolve("static").resolve("crypta-platform.js"))
            .contains("window.CryptaPlatform"));
  }

  @Test
  void init_whenNoPermissionsRequested_expectManifestOmitsBlankPermissions() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertFalse(manifest.contains("app.permissions="));
    assertTrue(manifest.contains("api.minimumVersion=" + currentContractVersion() + "\n"));
    assertTrue(manifest.contains("api.maximumTestedVersion=" + currentContractVersion() + "\n"));
    assertTrue(manifest.contains("api.targetStability=stable\n"));
    assertTrue(manifest.contains("api.experimentalCapabilitiesAccepted=false\n"));
  }

  @Test
  void init_whenPermissionCaseNeedsNormalization_expectDisclosureAndManifestUseCanonicalValue()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "Queue.Read");

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);
    String indexHtml =
        Files.readString(appDir.resolve("static").resolve("index.html"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(manifest.contains("app.permissions=queue.read\n"));
    assertTrue(indexHtml.contains("<code>queue.read</code>"));
    assertFalse(indexHtml.contains("Queue.Read"));
  }

  @Test
  void init_whenExperimentalPermissionRequested_expectExperimentalMetadataAndStrictValidation()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.identities.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(manifest.contains("app.permissions=vault.identities.read\n"));
    assertTrue(manifest.contains("api.targetStability=experimental\n"));
    assertTrue(manifest.contains("api.experimentalCapabilitiesAccepted=true\n"));
    assertEquals("", result.err());
  }

  @Test
  void init_whenOperatorOnlyPermissionRequested_expectFailureBeforeManifestWrite() {
    Path appDir = tempDir.resolve("sample-app");

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--permission",
            "vault.identities.manage");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("permission vault.identities.manage is operator-only"));
    assertFalse(Files.exists(appDir.resolve("cryptad-app.properties")));
  }

  @Test
  void init_whenShellPanelRequested_expectManifestUsesShellPanelWithoutStaticTemplate()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--ui-mode",
            "shell-panel");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(manifest.contains("app.ui.mode=shell-panel\n"));
    assertTrue(manifest.contains("app.ui.entry=/app/node/#sample-app\n"));
    assertFalse(Files.exists(appDir.resolve("static")));
  }

  @Test
  void init_whenTargetDirectoryIsNotEmptyWithoutOverwrite_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Files.createDirectories(appDir);
    Files.writeString(appDir.resolve("existing.txt"), "existing", StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("target directory is not empty"));
  }

  @Test
  void init_whenTargetDirectoryIsSymbolicLink_expectFailureWithoutWritingThroughLink()
      throws Exception {
    Path externalTarget = tempDir.resolve("external-target");
    Path appDir = tempDir.resolve("linked-app");
    Files.createDirectories(externalTarget);
    Assumptions.assumeTrue(canCreateSymlink(appDir));
    Files.createSymbolicLink(appDir, externalTarget);

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--overwrite");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("target directory must not be a symbolic link"));
    assertFalse(Files.exists(externalTarget.resolve("cryptad-app.properties")));
  }

  @Test
  void validate_whenScaffoldIsMinimal_expectSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
    assertEquals("", result.err());
  }

  @Test
  void uiLint_whenScaffoldedStaticAppCheckedStrict_expectSuccessAndJson() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path json = tempDir.resolve("reports").resolve("ui-lint.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");

    CliResult result =
        runCli(
            "ui", "lint", "--bundle-dir", appDir.toString(), "--strict", "--json", json.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint passed: 0 error(s)"));
    String jsonText = Files.readString(json, StandardCharsets.UTF_8);
    assertTrue(jsonText.contains("\"appId\": \"sample-app\""));
    assertTrue(jsonText.contains("\"uiMode\": \"static\""));
    assertTrue(jsonText.contains("\"findings\": []"));
    assertFalse(jsonText.contains(tempDir.toString()));
  }

  @Test
  void uiLint_whenStaticEntryIsNotHtml_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.move(staticDir.resolve("index.html"), staticDir.resolve("index.txt"));
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.ui.entry=static/index.html\n", "app.ui.entry=static/index.txt\n"),
        StandardCharsets.UTF_8);

    CliResult lintResult = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");
    CliResult validateResult = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, lintResult.exitCode());
    assertTrue(lintResult.err().contains("static-entry-non-html"));
    assertTrue(lintResult.err().contains("application/octet-stream"));
    assertTrue(lintResult.err().contains("static/index.txt"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, validateResult.exitCode());
    assertTrue(validateResult.err().contains("static-entry-non-html"));
  }

  @Test
  void uiLint_whenStaticEntryParentIsSymbolicLink_expectFailureWithoutReadingExternalUi()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Path externalStaticDir = tempDir.resolve("external-static");
    Files.move(staticDir, externalStaticDir);
    Assumptions.assumeTrue(canCreateSymlink(staticDir));
    Files.createSymbolicLink(staticDir, externalStaticDir);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("static-entry-missing"));
    assertTrue(result.err().contains("static/index.html"));
  }

  @Test
  void uiLint_whenLocalScriptAndStylesheetReferencesAreMissing_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.delete(appDir.resolve("static").resolve("crypta-platform.js"));
    Files.delete(appDir.resolve("static").resolve("app.js"));
    Files.delete(appDir.resolve("static").resolve("app.css"));

    CliResult lintResult = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");
    CliResult validateResult = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, lintResult.exitCode());
    assertTrue(lintResult.err().contains("local-ui-reference-missing"));
    assertTrue(lintResult.err().contains("static/crypta-platform.js"));
    assertTrue(lintResult.err().contains("static/app.js"));
    assertTrue(lintResult.err().contains("static/app.css"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, validateResult.exitCode());
    assertTrue(validateResult.err().contains("UI lint failed"));
    assertTrue(validateResult.err().contains("local-ui-reference-missing"));
  }

  @Test
  void uiLint_whenLocalScriptParentIsSymbolicLink_expectFailureWithoutReadingExternalAsset()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Path externalAssetDir = tempDir.resolve("external-assets");
    Files.createDirectories(externalAssetDir);
    Files.writeString(
        externalAssetDir.resolve("app.js"),
        "CryptaPlatform.bootstrap.load().then(() => undefined);\n",
        StandardCharsets.UTF_8);
    Path linkedAssetDir = staticDir.resolve("linked");
    Assumptions.assumeTrue(canCreateSymlink(linkedAssetDir));
    Files.createSymbolicLink(linkedAssetDir, externalAssetDir);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./linked/app.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-missing"));
    assertTrue(result.err().contains("static/linked/app.js"));
  }

  @Test
  void uiLint_whenLocalScriptAndStylesheetUseUnsupportedTypes_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.move(staticDir.resolve("app.js"), staticDir.resolve("app.jsx"));
    Files.move(staticDir.resolve("app.css"), staticDir.resolve("app.scss"));
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("./app.js", "./app.jsx")
            .replace("./app.css", "./app.scss"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-unsupported-type"));
    assertTrue(result.err().contains("static/app.jsx"));
    assertTrue(result.err().contains("static/app.scss"));
  }

  @Test
  void uiLint_whenLocalReferencesAreNotRouteSafe_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(staticDir.resolve("foo:bar.css"), "body {}\n", StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("./app.js", "../../app.js")
            .replace("./app.css", "./foo:bar.css"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-route-invalid"));
    assertTrue(result.err().contains("../app.js"));
    assertTrue(result.err().contains("static/foo:bar.css"));
  }

  @Test
  void uiLint_whenAbsoluteScriptAndStylesheetReferencesPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("./app.js", "/api/v1/foo.js")
            .replace("./app.css", "/theme.css"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-route-invalid"));
    assertTrue(result.err().contains("/api/v1/foo.js"));
    assertTrue(result.err().contains("/theme.css"));
  }

  @Test
  void uiLint_whenLocalReferenceUsesRouteEncoding_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("space app.js"),
        Files.readString(staticDir.resolve("app.js"), StandardCharsets.UTF_8),
        StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./space%20app.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
  }

  @Test
  void uiLint_whenEncodedLoadedAppScriptOmitsBootstrap_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("space app.js"), "console.log('loaded');\n", StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./space%20app.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/space app.js"));
  }

  @Test
  void uiLint_whenBootstrapAppearsOnlyInCommentOrString_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        // TODO call CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        const example = "platform.bootstrap.load({ appId: 'sample-app' })";
        console.log(example);
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void uiLint_whenBootstrapFollowsRegexLiteralWithEscapedSlashes_expectStrictSuccess()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        const matcher = /^https?:\\/\\//; CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        console.log(matcher.test(window.location.href));
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
  }

  @Test
  void uiLint_whenBootstrapAppearsOnlyInRegexLiteral_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        const example = /CryptaPlatform.bootstrap.load()/;
        console.log(example);
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void uiLint_whenBootstrapUsesLargeMemberChain_expectStrictSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    StringBuilder script = new StringBuilder("const root = window.CryptaPlatform;\nroot");
    for (int index = 0; index < 2048; index++) {
      script.append(".member").append(index);
    }
    script.append(".bootstrap.load({ appId: \"sample-app\" });\n");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"), script.toString(), StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
  }

  @Test
  void uiLint_whenAppScriptLivesUnderCryptaUiDirectory_expectStrictBootstrapFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("crypta-ui").resolve("main.js"),
        "console.log('loaded app code');\n",
        StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./crypta-ui/main.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/crypta-ui/main.js"));
  }

  @Test
  void uiLint_whenCssImportUsesNonLocalScheme_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.css"),
        "\n@import url(\"data:text/css,body{}\");\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("non-local-css-import"));
    assertTrue(result.err().contains("static/app.css"));
  }

  @Test
  void uiLint_whenPermissionDisclosureOmitsDeclaredPermission_expectStrictFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read",
        "--permission",
        "queue.write");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("              <li><code>queue.write</code></li>\n", ""),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("permission-disclosure-missing-permission"));
    assertTrue(result.err().contains("queue.write"));
  }

  @Test
  void uiLint_whenPermissionDisclosureMentionsUndeclaredPermission_expectStrictFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                "              <li><code>queue.read</code></li>\n",
                """
                              <li><code>queue.read</code></li>
                              <li><code>content.insert</code></li>
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("permission-disclosure-undeclared-permission"));
    assertTrue(result.err().contains("content.insert"));
  }

  @Test
  void validate_whenStaticUiEntryUsesCustomRelativePath_expectStrictUiLintSuccess()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    Path uiDir = appDir.resolve("ui");
    Files.createDirectory(uiDir);
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.ui.entry=static/index.html\n", "app.ui.entry=ui/index.html\n"),
        StandardCharsets.UTF_8);
    Files.writeString(
        uiDir.resolve("index.html"),
        """
        <!doctype html>
        <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sample App</title>
            <link rel="stylesheet" href="../static/crypta-ui/crypta-ui-tokens.css">
            <link rel="stylesheet" href="../static/crypta-ui/crypta-ui.css">
            <link rel="stylesheet" href="./app.css">
          </head>
          <body class="cr-app">
            <main class="cr-shell">
              <h1>Sample App</h1>
              <section class="cr-permission-summary" data-crypta-permission-summary>
                <p><strong>Declared permissions</strong></p>
                <ul><li><code>queue.read</code></li></ul>
              </section>
              <p class="cr-status" id="status" role="status" aria-live="polite"></p>
            </main>
            <script src="../static/crypta-platform.js"></script>
            <script type="module" src="./main.js"></script>
          </body>
        </html>
        """,
        StandardCharsets.UTF_8);
    Files.writeString(uiDir.resolve("app.css"), ".custom { color: var(--cr-color-text); }\n");
    Files.writeString(
        uiDir.resolve("main.js"),
        """
        async function main() {
          await CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        }
        main();
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
    assertEquals("", result.err());
  }

  @Test
  void uiLint_whenCustomAppScriptLoadsBeforeSdk_expectStrictOrderFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <script src="./crypta-platform.js"></script>
                    <script type="module" src="./app.js"></script>
                """,
                """
                    <script src="./main.js"></script>
                    <script src="./crypta-platform.js"></script>
                """),
        StandardCharsets.UTF_8);
    Files.writeString(
        appDir.resolve("static").resolve("main.js"),
        """
        async function main() {
          await CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        }
        main();
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-script-order"));
  }

  @Test
  void uiLint_whenDeferredSdkPrecedesParserBlockingAppScript_expectStrictOrderFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <script src="./crypta-platform.js"></script>
                    <script type="module" src="./app.js"></script>
                """,
                """
                    <script src="./crypta-platform.js" defer></script>
                    <script src="./app.js"></script>
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-script-defer-order"));
  }

  @Test
  void uiLint_whenRemoteScriptPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                "<script src=\"./crypta-platform.js\"></script>",
                "<script src=\"https://cdn.example.invalid/platform.js\"></script>"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("remote-script"));
  }

  @Test
  void uiLint_whenInlineScriptAndEventHandlerPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("<body class=\"cr-app\">", "<body class=\"cr-app\" onclick=\"void 0\">")
            .replace("</body>", "<script>window.inline = true;</script>\n</body>"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("inline-event-handler"));
    assertTrue(result.err().contains("inline-script"));
  }

  @Test
  void uiLint_whenForbiddenTokenTextPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        "\nconsole.log('CRYPTAD_APP_TOKEN');\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("forbidden-token-text"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void uiLint_whenUnsafeLocalJavaScriptPatternsPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        async function main() {
          await CryptaPlatform.bootstrap.load({ appId: "sample-app" });
          eval("console.log('unsafe')");
          const factory = new Function("return 1");
          localStorage.setItem("session", "value");
          await fetch("/api/v1/queue");
          return factory();
        }
        main();
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("dynamic-code-evaluation"));
    assertTrue(result.err().contains("persistent-browser-storage"));
    assertTrue(result.err().contains("direct-platform-api-reference"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void validate_whenStrictStaticUiLintFindsProblem_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("    <link rel=\"stylesheet\" href=\"./crypta-ui/crypta-ui.css\">\n", ""),
        StandardCharsets.UTF_8);

    CliResult normalResult = runCli("validate", "--bundle-dir", appDir.toString());
    CliResult strictResult = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, normalResult.exitCode());
    assertEquals(CommandLine.ExitCode.SOFTWARE, strictResult.exitCode());
    assertTrue(strictResult.err().contains("design-system-css-not-linked"));
    assertTrue(strictResult.err().contains("UI lint failed"));
  }

  @Test
  void uiLint_whenCanonicalDesignSystemAssetIsModified_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui.css"),
        "\n.modified {}\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("design-system-asset-modified"));
    assertTrue(result.err().contains("static/crypta-ui/crypta-ui.css"));
  }

  @Test
  void uiLint_whenDesignSystemTokensLoadAfterBaseCss_expectStrictOrderFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                """,
                """
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("design-system-css-order"));
  }

  @Test
  void uiLint_whenNonCanonicalCryptaUiStylesheetLoadsBeforeTokens_expectStrictOrderFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("crypta-ui").resolve("custom.css"),
        ".cr-app { color: inherit; }\n",
        StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                """,
                """
                    <link rel="stylesheet" href="./crypta-ui/custom.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("design-system-css-order"));
  }

  @Test
  void uiLint_whenUiModeIsNone_expectNotApplicableSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--ui-mode",
        "none");

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint not applicable for app.ui.mode=none"));
  }

  @Test
  void uiLint_whenUiModeIsShellPanel_expectNotApplicableSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--ui-mode",
        "shell-panel");

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint not applicable for app.ui.mode=shell-panel"));
  }

  @Test
  void apiSnapshot_whenOutputRequested_expectContractJsonWritten() throws Exception {
    Path contractFile = tempDir.resolve("platform-api-contract.json");

    CliResult result = runCli("api", "snapshot", "--output", contractFile.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Wrote Platform API contract"));
    String json = Files.readString(contractFile, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"contractVersion\":" + currentContractVersion()));
    assertTrue(json.contains("\"platform.contract.read\""));
  }

  @Test
  void compatVerify_whenBundleTargetsCurrentContract_expectSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");

    CliResult result = runCli("compat", "verify", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Compatibility verified."));
    assertEquals("", result.err());
  }

  @Test
  void compatVerify_whenCatalogEntryApiRangeOmitsTargetStability_expectManifestTargetIsUsed()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "api.minimumVersion=" + currentContractVersion(),
            "api.maximumTestedVersion=" + currentContractVersion()),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("compat", "verify", "--catalog-entry", descriptor.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Compatibility verified."));
    assertEquals("", result.err());
  }

  @Test
  void
      compatVerify_whenCatalogEntryExperimentalTargetOmitsAcceptance_expectManifestAcceptanceIsUsed()
          throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.identities.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "api.targetStability=experimental"),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("compat", "verify", "--catalog-entry", descriptor.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Compatibility verified."));
    assertEquals("", result.err());
  }

  @Test
  void compatVerify_whenCatalogEntryExplicitlyRejectsManifestAcceptance_expectFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.identities.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "api.targetStability=experimental",
            "api.experimentalCapabilitiesAccepted=false"),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("compat", "verify", "--catalog-entry", descriptor.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(
        result
            .err()
            .contains(
                "Experimental capability requires api.experimentalCapabilitiesAccepted=true"));
  }

  @Test
  void compatVerify_whenStrictBundleMinimumExceedsContract_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path manifest = appDir.resolve("cryptad-app.properties");
    int futureContractVersion = currentContractVersion() + 1;
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace(
                "api.minimumVersion=" + currentContractVersion(),
                "api.minimumVersion=" + futureContractVersion)
            .replace(
                "api.maximumTestedVersion=" + currentContractVersion(),
                "api.maximumTestedVersion=" + futureContractVersion),
        StandardCharsets.UTF_8);

    CliResult result = runCli("compat", "verify", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("requires Platform API contract " + futureContractVersion));
  }

  @Test
  void validate_whenBundleIsBroken_expectFailureMessage() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.delete(appDir.resolve("bin").resolve("start.sh"));

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("app.exec does not resolve to a file"));
  }

  @Test
  void validate_whenUnknownPermissionAndStrict_expectFailure() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "future.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("unknown app permission(s): future.read"));
  }

  @Test
  void validate_whenUnknownPermissionAndNotStrict_expectWarningAndSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "future.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.err().contains("Warning: unknown app permission(s): future.read"));
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
  }

  @Test
  void validate_whenVaultPermissionsAndStrict_expectRecognizedByValidationAndUiLint()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.secrets.read",
        "--permission",
        "vault.identities.use");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);
    String indexHtml =
        Files.readString(appDir.resolve("static").resolve("index.html"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
    assertEquals("", result.err());
    assertTrue(manifest.contains("api.targetStability=experimental\n"));
    assertTrue(manifest.contains("api.experimentalCapabilitiesAccepted=true\n"));
    assertTrue(indexHtml.contains("<code>vault.secrets.read</code>"));
    assertTrue(indexHtml.contains("<code>vault.identities.use</code>"));
  }

  @Test
  void signAndVerify_whenBundleCliRoundTrips_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("private.der");
    Path publicKey = tempDir.resolve("public.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.write(publicKey, keyPair.getPublic().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult signResult =
        runCli(
            "sign",
            "--bundle-dir",
            appDir.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    CliResult verifyResult =
        runCli(
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--trusted-key-id",
            "dev-local",
            "--trusted-public-key-file",
            publicKey.toString());

    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed bundle:"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified bundle:"));
  }

  @Test
  void pack_whenScaffoldIsValid_expectZipArtifact() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult result =
        runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(Files.isRegularFile(outputZip));
    assertTrue(result.out().contains("Packaged bundle:"));
    assertTrue(result.out().contains(sha256Hex(outputZip)));
  }

  @Test
  void pack_whenOutputExistsWithoutOverwrite_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(outputZip, "existing");

    CliResult result =
        runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("output ZIP already exists"));
  }

  @Test
  void catalogCreate_whenDescriptorPointsAtBundleZip_expectCatalogWithComputedArtifactMetadata()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "homepage=https://example.invalid/sample-app",
            "source=https://example.invalid/sample-app/source",
            "license=MIT",
            "categories=Productivity,network",
            "minimumCryptaVersion=0.1.0",
            "maximumCryptaVersion=0.9.99",
            "channel=beta",
            "support.status=experimental",
            "deprecation.status=deprecated",
            "deprecation.message=Use Sample App stable.",
            "replacementAppId=sample-app-stable",
            "securityAdvisories=CRYPTA-2026-0001",
            "securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001",
            "maintenance.owner=crypta-core",
            "maintenance.ownerUri=https://example.invalid/crypta/owners/core",
            "maintenance.supportLevel=maintained",
            "maintenance.dataSchemaPolicy=stateless",
            "maintenance.migrationPolicy=none",
            "maintenance.backupRestore=not-applicable",
            "maintenance.securityPolicy=catalog-advisories",
            "maintenance.deprecationPolicy=none",
            "maintenance.supportUri=https://example.invalid/crypta/apps/sample-app/support",
            "review.status=reviewed",
            "review.note=Reviewed for local operator safety.",
            "permissions.rationale.queue.read=Reads the local transfer queue.",
            "screenshot.1=https://example.invalid/sample-app/shot-1.png",
            "changelog.summary=Adds queue retry controls.",
            "changelog.uri=https://example.invalid/sample-app/changelog.txt"),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--generated-at",
            "2026-04-29T00:00:00Z",
            "--entry",
            descriptor.toString());

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    List<String> expectedCatalogFragments =
        List.of(
            "catalog.version=5\n",
            "catalog.generatedAt=2026-04-29T00:00:00Z\n",
            "app.sample-app.id=sample-app\n",
            "app.sample-app.homepage=https://example.invalid/sample-app\n",
            "app.sample-app.source=https://example.invalid/sample-app/source\n",
            "app.sample-app.license=MIT\n",
            "app.sample-app.categories=productivity,network\n",
            "app.sample-app.minimumCryptaVersion=0.1.0\n",
            "app.sample-app.maximumCryptaVersion=0.9.99\n",
            "app.sample-app.channel=beta\n",
            "app.sample-app.support.status=experimental\n",
            "app.sample-app.deprecation.status=deprecated\n",
            "app.sample-app.replacementAppId=sample-app-stable\n",
            "app.sample-app.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001\n",
            "app.sample-app.maintenance.owner=crypta-core\n",
            "app.sample-app.maintenance.ownerUri=https://example.invalid/crypta/owners/core\n",
            "app.sample-app.maintenance.supportLevel=maintained\n",
            "app.sample-app.maintenance.dataSchemaPolicy=stateless\n",
            "app.sample-app.maintenance.migrationPolicy=none\n",
            "app.sample-app.maintenance.backupRestore=not-applicable\n",
            "app.sample-app.maintenance.securityPolicy=catalog-advisories\n",
            "app.sample-app.maintenance.deprecationPolicy=none\n",
            "app.sample-app.maintenance.supportUri=https://example.invalid/crypta/apps/sample-app/support\n",
            "app.sample-app.api.minimumVersion=" + currentContractVersion() + "\n",
            "app.sample-app.api.maximumTestedVersion=" + currentContractVersion() + "\n",
            "app.sample-app.api.targetStability=stable\n",
            "app.sample-app.api.experimentalCapabilitiesAccepted=false\n",
            "app.sample-app.review.status=reviewed\n",
            "app.sample-app.review.note=Reviewed for local operator safety.\n",
            "app.sample-app.permissions.rationale.queue.read=Reads the local transfer queue.\n",
            "app.sample-app.screenshot.1=https://example.invalid/sample-app/shot-1.png\n",
            "app.sample-app.changelog.summary=Adds queue retry controls.\n",
            "app.sample-app.changelog.uri=https://example.invalid/sample-app/changelog.txt\n",
            "app.sample-app.permissions=queue.read\n",
            "app.sample-app.bundle.size.bytes=" + Files.size(outputZip),
            "app.sample-app.bundle.sha256=" + sha256Hex(outputZip));
    List<String> missingCatalogFragments =
        expectedCatalogFragments.stream().filter(fragment -> !catalog.contains(fragment)).toList();

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Created catalog: dev with 1 entry"));
    assertEquals(List.of(), missingCatalogFragments);
  }

  @Test
  void catalogCreate_whenSecurityPolicyFlagsProvided_expectVersionFourPolicyWritten()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString(),
            "--security-advisory-record",
            String.join(
                ";",
                "id=CRYPTA-2026-0001",
                "uri=https://example.invalid/advisories/CRYPTA-2026-0001",
                "title=Sample App 0.1.0 vulnerable",
                "severity=critical",
                "status=active",
                "action=denylist",
                "summary=Upgrade to a reviewed replacement.",
                "publishedAt=2026-06-11T00:00:00Z",
                "updatedAt=2026-06-11T00:00:00Z",
                "replacementAppId=sample-app",
                "safeUninstallGuidance=Export app data before removal."),
            "--security-denylist-entry",
            String.join(
                ";",
                "id=deny-sample-app-0-1-0",
                "appId=sample-app",
                "version=0.1.0",
                "advisoryId=CRYPTA-2026-0001",
                "reason=Known vulnerable release.",
                "replacementAppId=sample-app",
                "safeUninstallGuidance=Export app data before removal."));

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Created catalog: dev with 1 entry"));
    assertTrue(catalog.contains("catalog.version=4\n"));
    assertTrue(catalog.contains("catalog.securityAdvisories=CRYPTA-2026-0001\n"));
    assertTrue(catalog.contains("catalog.securityAdvisory.CRYPTA-2026-0001.action=denylist\n"));
    assertTrue(
        catalog.contains(
            "catalog.securityAdvisory.CRYPTA-2026-0001.safeUninstallGuidance=Export app data before"
                + " removal.\n"));
    assertTrue(catalog.contains("catalog.securityDenylist=deny-sample-app-0-1-0\n"));
    assertTrue(catalog.contains("catalog.securityDenylist.deny-sample-app-0-1-0.version=0.1.0\n"));
    assertTrue(
        catalog.contains(
            "catalog.securityDenylist.deny-sample-app-0-1-0.advisoryId=CRYPTA-2026-0001\n"));
  }

  @Test
  void catalogCreate_whenDescriptorUsesCryptaChkBundleUri_expectCatalogWithCryptaArtifact()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=crypta:CHK@sample-bundle",
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString());

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(catalog.contains("app.sample-app.bundle.uri=crypta:CHK@sample-bundle\n"));
    assertTrue(catalog.contains("app.sample-app.bundle.size.bytes=" + Files.size(outputZip)));
    assertTrue(catalog.contains("app.sample-app.bundle.sha256=" + sha256Hex(outputZip)));
  }

  @Test
  void catalogCreate_whenDescriptorUsesMutableCryptaBundleUri_expectInvalidArtifactFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=crypta:SSK@sample-bundle",
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("artifact URI must use an immutable CHK key"));
  }

  @Test
  void reviewSignVerifyAndCatalogCreate_whenReceiptIsTrusted_expectEmbeddedReceipt()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path receiptFile = tempDir.resolve("review-receipt.properties");
    Path trustedReviewers = tempDir.resolve("trusted-reviewers.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=1",
            "reviewer.1.id=dev-review",
            "reviewer.1.algorithm=Ed25519",
            "reviewer.1.public.key.base64="
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
            "reviewer.1.display.name=Development Review",
            "reviewer.1.policy.id=dev-review-v1"),
        StandardCharsets.UTF_8);
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult signResult =
        runCli(
            "review",
            "sign",
            "--catalog-entry",
            descriptor.toString(),
            "--receipt-file",
            receiptFile.toString(),
            "--reviewer-key-id",
            "dev-review",
            "--reviewer-private-key-file",
            privateKey.toString(),
            "--policy-id",
            "dev-review-v1",
            "--policy-version",
            "1",
            "--status",
            "reviewed",
            "--reviewed-at",
            "2026-05-01T00:00:00Z");
    CliResult verifyResult =
        runCli(
            "review",
            "verify",
            "--catalog-entry",
            descriptor.toString(),
            "--receipt-file",
            receiptFile.toString(),
            "--trusted-reviewer-keys-file",
            trustedReviewers.toString());
    CliResult catalogResult =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString(),
            "--review-receipt",
            receiptFile.toString());

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed review receipt: sample-app 0.1.0 reviewed"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified review receipt: trusted_reviewed"));
    assertEquals(CommandLine.ExitCode.OK, catalogResult.exitCode());
    assertTrue(catalog.contains("app.sample-app.review.receipt.status=reviewed\n"));
    assertTrue(catalog.contains("app.sample-app.review.receipt.reviewer.key.id=dev-review\n"));
    assertTrue(catalog.contains("app.sample-app.review.receipt.signature.value.base64="));
  }

  @Test
  void reviewFingerprint_whenReceiptProvided_expectRedactedFingerprintSummary() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path receiptFile = tempDir.resolve("review-receipt.properties");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);
    runCli(
        "review",
        "sign",
        "--catalog-entry",
        descriptor.toString(),
        "--receipt-file",
        receiptFile.toString(),
        "--reviewer-key-id",
        "dev-review",
        "--reviewer-private-key-file",
        privateKey.toString(),
        "--policy-id",
        "dev-review-v1",
        "--policy-version",
        "1",
        "--status",
        "reviewed",
        "--reviewed-at",
        "2026-05-01T00:00:00Z");

    CliResult result = runCli("review", "fingerprint", "--receipt-file", receiptFile.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(
        result
            .out()
            .matches(
                "(?s).*Review receipt fingerprint: fingerprintSha256=[0-9a-f]{64} "
                    + "payloadSha256=[0-9a-f]{64} reviewer=dev-review.*"));
    assertFalse(result.out().contains("signature.value.base64"));
    assertFalse(result.out().contains(privateKey.toString()));
  }

  @Test
  void reviewTransparencyVerify_whenLogFileIsMissing_expectFailure() {
    Path missingLog = tempDir.resolve("missing-review-transparency-log.jsonl");

    CliResult result =
        runCli("review", "transparency", "verify", "--log-file", missingLog.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("review transparency log file not found"));
    assertFalse(result.out().contains("Verified review transparency log"));
  }

  @Test
  void catalogSignAndVerify_whenCatalogCliRoundTrips_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("catalog-private.der");
    Path publicKey = tempDir.resolve("catalog-public.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.write(publicKey, keyPair.getPublic().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);
    runCli(
        "catalog",
        "create",
        "--catalog-file",
        catalogFile.toString(),
        "--catalog-id",
        "dev",
        "--name",
        "Development Apps",
        "--entry",
        descriptor.toString());
    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);

    assertTrue(catalog.contains("catalog.version=2\n"));
    assertTrue(
        catalog.contains("app.sample-app.api.minimumVersion=" + currentContractVersion() + "\n"));
    assertTrue(catalog.contains("app.sample-app.api.targetStability=stable\n"));
    assertTrue(catalog.contains("app.sample-app.api.experimentalCapabilitiesAccepted=false\n"));
    CliResult signResult =
        runCli(
            "catalog",
            "sign",
            "--catalog-file",
            catalogFile.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    CliResult verifyResult =
        runCli(
            "catalog",
            "verify",
            "--catalog-file",
            catalogFile.toString(),
            "--trusted-key-id",
            "dev-local",
            "--trusted-public-key-file",
            publicKey.toString());

    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed catalog with key: dev-local"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified catalog: dev"));
  }

  @Test
  void help_whenRequested_expectUsage() {
    CliResult result = runCli("--help");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Usage: crypta-app"));
    assertTrue(result.out().contains("init"));
    assertTrue(result.out().contains("validate"));
    assertTrue(result.out().contains("pack"));
    assertTrue(result.out().contains("api"));
    assertTrue(result.out().contains("compat"));
    assertTrue(result.out().contains("ui"));
    assertTrue(result.out().contains("review"));
    assertTrue(result.out().contains("catalog"));
    assertTrue(result.out().contains("submission"));
  }

  @Test
  void submissionHelp_whenRequested_expectWorkflowCommands() {
    CliResult result = runCli("submission");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("create"));
    assertTrue(result.out().contains("verify"));
    assertTrue(result.out().contains("pre-review"));
    assertTrue(result.out().contains("decide"));
    assertTrue(result.out().contains("catalog-candidate"));
  }

  @Test
  void submissionCreate_whenInitializedStaticBundleIncludesSdk_expectAccepted() {
    Path appDir = tempDir.resolve("sdk-template-app");
    Path submission = tempDir.resolve("sdk-template-submission.zip");
    CliResult init =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sdk-template-app",
            "--name",
            "SDK Template App",
            "--version",
            "1.0.0");

    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/sdk-template-app",
            "--non-production");

    assertEquals(CommandLine.ExitCode.OK, init.exitCode(), init.err());
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertTrue(Files.isRegularFile(submission));
    assertFalse(create.err().contains("redaction.session-token"));
  }

  @Test
  void submissionVerifyJson_whenRedactionBlockerIsInMetadata_expectRedactedSummary()
      throws Exception {
    Path appDir = createSubmissionBundle("json-leak-app", "JSON Leak App", "1.0.0");
    Path submission = tempDir.resolve("json-leak-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/json-leak-app",
            "--non-production");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    String token = "Bearer abcdefghijklmnop";
    String metadata =
        readSubmissionMetadataText(submission)
            .replace(
                "\"sourceReference\":{\"url\":\"https://example.invalid/json-leak-app\"}",
                "\"sourceReference\":{\"url\":\"https://example.invalid/json-leak-app\","
                    + "\"revision\":\""
                    + token
                    + "\"}");
    Path tampered = tempDir.resolve("json-leak-tampered.zip");
    writeZipWithReplacements(
        submission,
        tampered,
        Map.of(
            SUBMISSION_METADATA_ENTRY,
            metadata.getBytes(StandardCharsets.UTF_8),
            "metadata/source.json",
            ("{\"url\":\"https://example.invalid/json-leak-app\",\"revision\":\"" + token + "\"}\n")
                .getBytes(StandardCharsets.UTF_8)));

    CliResult result =
        runCli("submission", "verify", "--submission", tampered.toString(), "--json");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.out().contains("\"redacted\":true"));
    assertTrue(result.out().contains("redaction.bearer-token"));
    assertFalse(result.out().contains(token));
    assertFalse(result.out().contains("sourceReference"));
    assertTrue(result.err().contains("redaction.bearer-token"));
    assertFalse(result.err().contains(token));
  }

  @Test
  void redactedMessage_whenExceptionContainsCommonAbsolutePaths_expectPathsRedacted() {
    String redacted =
        CryptaAppCli.redactedMessage(
            new IllegalArgumentException(
                "failed /var/folders/aa/app/index.html and /opt/crypta/bin/tool and"
                    + " C:\\Users\\Alice\\secret.txt"));

    assertTrue(redacted.contains("[redacted-path]"));
    assertFalse(redacted.contains("/var/folders"));
    assertFalse(redacted.contains("/opt/crypta"));
    assertFalse(redacted.contains("C:\\Users\\Alice"));
  }

  @Test
  void submissionCatalogCandidate_whenSubmissionIsResubmission_expectDescriptorPreservesLink()
      throws Exception {
    Path appDir = createSubmissionBundle("resubmitted-app", "Resubmitted App", "1.0.0");
    Path submission = tempDir.resolve("resubmitted-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "resubmission",
            "--resubmission-of",
            "previous-submission",
            "--submission-id",
            "current-submission",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/resubmitted-app",
            "--non-production");
    Path preReview = tempDir.resolve("resubmitted-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path reason = tempDir.resolve("review-reason.md");
    Files.writeString(reason, "Reviewed resubmission.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("review-receipt.properties");
    CliResult decide =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");
    Path descriptor = tempDir.resolve("resubmitted-catalog-entry.properties");
    CliResult candidate =
        runCli(
            "submission",
            "catalog-candidate",
            "--submission",
            submission.toString(),
            "--review-receipt",
            receipt.toString(),
            "--output",
            descriptor.toString());

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());
    assertEquals(CommandLine.ExitCode.OK, decide.exitCode(), decide.err());
    assertEquals(CommandLine.ExitCode.OK, candidate.exitCode(), candidate.err());
    String preReviewDigest = sha256Hex(preReview);
    String reasonDigest = sha256Hex(reason);
    String receiptText = Files.readString(receipt, StandardCharsets.UTF_8);
    assertTrue(receiptText.contains("review.receipt.version=2\n"));
    assertTrue(receiptText.contains("review.receipt.evidence.sha256=" + preReviewDigest + "\n"));
    assertTrue(
        receiptText.contains("review.receipt.decision.reason.sha256=" + reasonDigest + "\n"));
    String descriptorText = Files.readString(descriptor, StandardCharsets.UTF_8);
    assertTrue(descriptorText.contains("review.resubmissionOf=previous-submission\n"));
    assertTrue(descriptorText.contains("review.preReview.sha256=" + preReviewDigest + "\n"));
    assertTrue(descriptorText.contains("review.decision.reason.sha256=" + reasonDigest + "\n"));
    assertTrue(descriptorText.contains("review.receipt.status=reviewed\n"));
    assertTrue(descriptorText.contains("review.receipt.signature.value.base64="));
    Path catalog = tempDir.resolve("resubmitted-catalog.properties");
    CliResult catalogCreate =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalog.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString());
    assertEquals(CommandLine.ExitCode.OK, catalogCreate.exitCode(), catalogCreate.err());
    String catalogText = Files.readString(catalog, StandardCharsets.UTF_8);
    assertTrue(catalogText.contains("catalog.version=6\n"));
    assertTrue(
        catalogText.contains("app.resubmitted-app.review.preReview.sha256=" + preReviewDigest));
    assertTrue(
        catalogText.contains("app.resubmitted-app.review.decision.reason.sha256=" + reasonDigest));
    assertTrue(catalogText.contains("app.resubmitted-app.review.receipt.status=reviewed\n"));
    assertTrue(catalogText.contains("app.resubmitted-app.review.receipt.signature.value.base64="));
  }

  @Test
  void submissionCatalogCandidate_whenVersionContainsUriReservedCharacters_expectDefaultUriIsSafe()
      throws Exception {
    Path appDir =
        createSubmissionBundle("reserved-version-app", "Reserved Version App", "1.0 beta");
    Path submission = tempDir.resolve("reserved-version-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/reserved-version-app",
            "--non-production");
    Path preReview = tempDir.resolve("reserved-version-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("reserved-version-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path reason = tempDir.resolve("reserved-version-review-reason.md");
    Files.writeString(reason, "Reviewed reserved version.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("reserved-version-review-receipt.properties");
    CliResult decide =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");
    Path descriptor = tempDir.resolve("reserved-version-catalog-entry.properties");
    CliResult candidate =
        runCli(
            "submission",
            "catalog-candidate",
            "--submission",
            submission.toString(),
            "--review-receipt",
            receipt.toString(),
            "--output",
            descriptor.toString());

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());
    assertEquals(CommandLine.ExitCode.OK, decide.exitCode(), decide.err());
    assertEquals(CommandLine.ExitCode.OK, candidate.exitCode(), candidate.err());
    String descriptorText = Files.readString(descriptor, StandardCharsets.UTF_8);
    assertTrue(
        descriptorText.contains(
            "bundle.uri=https://example.invalid/crypta-apps/reserved-version-app-1_0_beta.zip\n"));
  }

  @Test
  void submissionCatalogCandidate_whenReceiptLacksSubmissionEvidence_expectFailure()
      throws Exception {
    Path appDir = createSubmissionBundle("legacy-receipt-app", "Legacy Receipt App", "1.0.0");
    Path submission = tempDir.resolve("legacy-receipt-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/legacy-receipt-app",
            "--non-production");
    Path artifact = tempDir.resolve("legacy-receipt-app-bundle.zip");
    writeSubmissionBundleArtifact(submission, artifact);
    Path legacyDescriptor = tempDir.resolve("legacy-receipt-entry.properties");
    Files.writeString(
        legacyDescriptor,
        lines(
            "artifact.path=" + artifact.toAbsolutePath().normalize(),
            "bundle.uri=" + artifact.toUri(),
            "summary=Legacy receipt catalog entry."),
        StandardCharsets.UTF_8);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("legacy-receipt-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path legacyReceipt = tempDir.resolve("legacy-review-receipt.properties");
    CliResult signLegacyReceipt =
        runCli(
            "review",
            "sign",
            "--catalog-entry",
            legacyDescriptor.toString(),
            "--receipt-file",
            legacyReceipt.toString(),
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key-file",
            privateKey.toString(),
            "--policy-id",
            "dev-review",
            "--policy-version",
            "1",
            "--status",
            "reviewed",
            "--reviewed-at",
            "2026-06-18T00:00:00Z");
    Path candidateDescriptor = tempDir.resolve("legacy-receipt-candidate.properties");

    CliResult candidate =
        runCli(
            "submission",
            "catalog-candidate",
            "--submission",
            submission.toString(),
            "--review-receipt",
            legacyReceipt.toString(),
            "--output",
            candidateDescriptor.toString());

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, signLegacyReceipt.exitCode(), signLegacyReceipt.err());
    assertEquals(CommandLine.ExitCode.SOFTWARE, candidate.exitCode());
    assertTrue(candidate.err().contains("require v2 review receipt evidence"));
    assertFalse(Files.exists(candidateDescriptor));
  }

  @Test
  void submissionDecide_whenRejectedReviewerFieldIsMultiline_expectFailure() throws Exception {
    Path appDir = createSubmissionBundle("rejected-app", "Rejected App", "1.0.0");
    Path submission = tempDir.resolve("rejected-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/rejected-app",
            "--non-production");
    Path preReview = tempDir.resolve("rejected-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    Path reason = tempDir.resolve("rejected-reason.md");
    Path rejection = tempDir.resolve("rejection.properties");
    Files.writeString(reason, "Rejected during metadata validation.\n", StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "rejected",
            "--reviewer-key-id",
            "reviewer-dev\npolicy.id=injected",
            "--rejection-output",
            rejection.toString(),
            "--reason",
            reason.toString(),
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("review.receipt.reviewer.key.id must be a single line"));
    assertTrue(Files.notExists(rejection));
  }

  @Test
  void submissionDecide_whenPreReviewDigestDoesNotMatchSubmission_expectFailure() throws Exception {
    Path appDir = createSubmissionBundle("reviewed-app", "Reviewed App", "1.0.0");
    Path submission = tempDir.resolve("reviewed-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/reviewed-app",
            "--non-production");
    Path preReview = tempDir.resolve("pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());
    String badDigest = "0".repeat(64);
    Path tamperedPreReview = tempDir.resolve("tampered-pre-review.json");
    Files.writeString(
        tamperedPreReview,
        Files.readString(preReview, StandardCharsets.UTF_8)
            .replaceAll(
                "\"bundleDigest\"\\s*:\\s*\"[0-9a-f]{64}\"",
                "\"bundleDigest\":\"" + badDigest + "\""),
        StandardCharsets.UTF_8);
    Path reason = tempDir.resolve("reason.md");
    Files.writeString(reason, "Rejected during digest binding check.\n", StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            tamperedPreReview.toString(),
            "--decision",
            "rejected",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reason",
            reason.toString(),
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("pre-review report bundleDigest does not match submission"));
  }

  @Test
  void submissionDecide_whenCautionDecisionIsLogged_expectTransparencyIsNotPositive()
      throws Exception {
    Path appDir = createSubmissionBundle("caution-app", "Caution App", "1.0.0");
    Path submission = tempDir.resolve("caution-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/caution-app",
            "--non-production");
    Path preReview = tempDir.resolve("caution-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("caution-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path reason = tempDir.resolve("caution-reason.md");
    Files.writeString(reason, "Accepted with reviewer caution.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("caution-review-receipt.properties");
    Path transparencyLog = tempDir.resolve("caution-transparency.jsonl");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "caution",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--transparency-log",
            transparencyLog.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    String logText = Files.readString(transparencyLog, StandardCharsets.UTF_8);
    assertTrue(logText.contains("\"receiptStatus\":\"caution\""));
    assertTrue(logText.contains("\"positive\":false"));
    assertFalse(logText.contains("\"positive\":true"));
  }

  @Test
  void submissionDecide_whenTrustedReviewerRegistryIsMissing_expectNoReceiptOrLogArtifacts()
      throws Exception {
    Path appDir = createSubmissionBundle("registry-fail-app", "Registry Fail App", "1.0.0");
    Path submission = tempDir.resolve("registry-fail-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/registry-fail-app",
            "--non-production");
    Path preReview = tempDir.resolve("registry-fail-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("registry-fail-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path reason = tempDir.resolve("registry-fail-reason.md");
    Files.writeString(reason, "Reviewed after automated checks.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("registry-fail-review-receipt.properties");
    Path transparencyLog = tempDir.resolve("registry-fail-transparency.jsonl");
    Path missingTrustedReviewers = tempDir.resolve("missing-trusted-reviewers.properties");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--trusted-reviewer-keys",
            missingTrustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--transparency-log",
            transparencyLog.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(Files.notExists(receipt));
    assertTrue(Files.notExists(transparencyLog));
  }

  @Test
  void submissionDecide_whenTrustedReviewerRegistryHasDifferentKey_expectNoReceiptOrLogArtifacts()
      throws Exception {
    Path appDir = createSubmissionBundle("registry-mismatch-app", "Registry Mismatch App", "1.0.0");
    Path submission = tempDir.resolve("registry-mismatch-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/registry-mismatch-app",
            "--non-production");
    Path preReview = tempDir.resolve("registry-mismatch-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair signingKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair registryKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("registry-mismatch-review-private.der");
    Files.write(privateKey, signingKeyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("registry-mismatch-trusted-reviewers.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=1",
            "reviewer.1.id=reviewer-dev",
            "reviewer.1.algorithm=Ed25519",
            "reviewer.1.public.key.base64="
                + Base64.getEncoder().encodeToString(registryKeyPair.getPublic().getEncoded()),
            "reviewer.1.display.name=Development Review",
            "reviewer.1.policy.id=crypta-app-review-v1"),
        StandardCharsets.UTF_8);
    Path reason = tempDir.resolve("registry-mismatch-reason.md");
    Files.writeString(reason, "Reviewed after automated checks.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("registry-mismatch-review-receipt.properties");
    Path transparencyLog = tempDir.resolve("registry-mismatch-transparency.jsonl");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--transparency-log",
            transparencyLog.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(
        result.err().contains("review receipt did not verify against trusted reviewer registry"));
    assertTrue(result.err().contains("invalid_signature"));
    assertTrue(Files.notExists(receipt));
    assertTrue(Files.notExists(transparencyLog));
  }

  private static void writeZipWithReplacements(
      Path source, Path target, Map<String, byte[]> replacements) throws Exception {
    LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
    try (ZipFile zip = new ZipFile(source.toFile())) {
      var enumeration = zip.entries();
      while (enumeration.hasMoreElements()) {
        ZipEntry entry = enumeration.nextElement();
        if (!entry.isDirectory()) {
          try (var input = zip.getInputStream(entry)) {
            entries.put(entry.getName(), input.readAllBytes());
          }
        }
      }
    }
    entries.putAll(replacements);
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target))) {
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        zip.putNextEntry(new ZipEntry(entry.getKey()));
        zip.write(entry.getValue());
        zip.closeEntry();
      }
    }
  }

  private static String readSubmissionMetadataText(Path source) throws Exception {
    try (ZipFile zip = new ZipFile(source.toFile())) {
      ZipEntry entry = zip.getEntry(SUBMISSION_METADATA_ENTRY);
      try (var input = zip.getInputStream(entry)) {
        return new String(input.readAllBytes(), StandardCharsets.UTF_8);
      }
    }
  }

  private static void writeSubmissionBundleArtifact(Path source, Path output) throws Exception {
    try (ZipFile zip = new ZipFile(source.toFile())) {
      ZipEntry entry = zip.getEntry(SUBMISSION_BUNDLE_ARTIFACT_ENTRY);
      assertTrue(entry != null);
      try (var input = zip.getInputStream(entry)) {
        Files.write(output, input.readAllBytes());
      }
    }
  }

  private Path createSubmissionBundle(String appId, String name, String version) throws Exception {
    Path bundle = tempDir.resolve(appId);
    Files.createDirectories(bundle.resolve("bin"));
    Files.writeString(
        bundle.resolve("cryptad-app.properties"),
        lines(
            "manifest.version=1",
            "app.id=" + appId,
            "app.name=" + name,
            "app.version=" + version,
            "app.exec=bin/start.sh",
            "api.minimumVersion=" + currentContractVersion(),
            "api.maximumTestedVersion=" + currentContractVersion(),
            "api.targetStability=stable",
            "api.experimentalCapabilitiesAccepted=false"),
        StandardCharsets.UTF_8);
    Files.writeString(
        bundle.resolve("bin/start.sh"), "#!/bin/sh\necho reviewed\n", StandardCharsets.UTF_8);
    return bundle;
  }

  private static String sha256Hex(Path file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] bytes = Files.readAllBytes(file);
    digest.update(bytes);
    StringBuilder builder = new StringBuilder(64);
    for (byte value : digest.digest()) {
      builder.append(Character.forDigit((value >>> 4) & 0x0F, 16));
      builder.append(Character.forDigit(value & 0x0F, 16));
    }
    return builder.toString();
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (UnsupportedOperationException | java.io.IOException | SecurityException _) {
      return false;
    }
  }

  private static CliResult runCli(String... arguments) {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    int exitCode =
        CryptaAppCli.execute(new PrintWriter(out, true), new PrintWriter(err, true), arguments);
    return new CliResult(exitCode, out.toString(), err.toString());
  }

  private record CliResult(int exitCode, String out, String err) {}

  private static int currentContractVersion() {
    return PlatformApiContract.current().contractVersion();
  }
}
