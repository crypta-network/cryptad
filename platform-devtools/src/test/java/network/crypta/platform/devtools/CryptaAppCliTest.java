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
    assertTrue(
        manifest.contains(
            "api.minimumVersion=" + PlatformApiContract.CURRENT_CONTRACT_VERSION + "\n"));
    assertTrue(
        manifest.contains(
            "api.maximumTestedVersion=" + PlatformApiContract.CURRENT_CONTRACT_VERSION + "\n"));
    assertTrue(manifest.contains("api.experimentalCapabilitiesAccepted=false\n"));
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
    assertTrue(json.contains("\"contractVersion\":2"));
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
    int futureContractVersion = PlatformApiContract.CURRENT_CONTRACT_VERSION + 1;
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace(
                "api.minimumVersion=" + PlatformApiContract.CURRENT_CONTRACT_VERSION,
                "api.minimumVersion=" + futureContractVersion)
            .replace(
                "api.maximumTestedVersion=" + PlatformApiContract.CURRENT_CONTRACT_VERSION,
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
    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Created catalog: dev with 1 entry"));
    assertTrue(catalog.contains("catalog.version=2\n"));
    assertTrue(catalog.contains("catalog.generatedAt=2026-04-29T00:00:00Z\n"));
    assertTrue(catalog.contains("app.sample-app.id=sample-app\n"));
    assertTrue(catalog.contains("app.sample-app.homepage=https://example.invalid/sample-app\n"));
    assertTrue(
        catalog.contains("app.sample-app.source=https://example.invalid/sample-app/source\n"));
    assertTrue(catalog.contains("app.sample-app.license=MIT\n"));
    assertTrue(catalog.contains("app.sample-app.categories=productivity,network\n"));
    assertTrue(catalog.contains("app.sample-app.minimumCryptaVersion=0.1.0\n"));
    assertTrue(
        catalog.contains(
            "app.sample-app.api.minimumVersion="
                + PlatformApiContract.CURRENT_CONTRACT_VERSION
                + "\n"));
    assertTrue(
        catalog.contains(
            "app.sample-app.api.maximumTestedVersion="
                + PlatformApiContract.CURRENT_CONTRACT_VERSION
                + "\n"));
    assertTrue(catalog.contains("app.sample-app.api.experimentalCapabilitiesAccepted=false\n"));
    assertTrue(catalog.contains("app.sample-app.review.status=reviewed\n"));
    assertTrue(
        catalog.contains("app.sample-app.review.note=Reviewed for local operator safety.\n"));
    assertTrue(
        catalog.contains(
            "app.sample-app.permissions.rationale.queue.read=Reads the local transfer queue.\n"));
    assertTrue(
        catalog.contains(
            "app.sample-app.screenshot.1=https://example.invalid/sample-app/shot-1.png\n"));
    assertTrue(catalog.contains("app.sample-app.changelog.summary=Adds queue retry controls.\n"));
    assertTrue(
        catalog.contains(
            "app.sample-app.changelog.uri=https://example.invalid/sample-app/changelog.txt\n"));
    assertTrue(catalog.contains("app.sample-app.permissions=queue.read\n"));
    assertTrue(catalog.contains("app.sample-app.bundle.size.bytes=" + Files.size(outputZip)));
    assertTrue(catalog.contains("app.sample-app.bundle.sha256=" + sha256Hex(outputZip)));
  }

  @Test
  void catalogCreate_whenDescriptorUsesCryptaBundleUri_expectUnsupportedArtifactSchemeFailure()
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
            "bundle.uri=crypta:CHK@sample-bundle?signature=CHK@sample-signature",
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
    assertTrue(result.err().contains("unsupported artifact URI scheme: crypta"));
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
        catalog.contains(
            "app.sample-app.api.minimumVersion="
                + PlatformApiContract.CURRENT_CONTRACT_VERSION
                + "\n"));
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
}
