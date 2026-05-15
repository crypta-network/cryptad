package network.crypta.platform.devtools;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.platform.devtools.devserver.CryptaAppDevServer;
import network.crypta.platform.devtools.devserver.DevServerConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class DeveloperBetaToolkitCliTest {
  private static final Pattern BOOTSTRAP_SESSION_PATTERN =
      Pattern.compile("\"browserSessionToken\"\\s*:\\s*\"([^\"]+)\"");

  @TempDir private Path tempDir;

  @Test
  void init_whenBetaTemplatesRequested_expectStrictTestCleanStaticApps() throws Exception {
    assertTemplate(
        "queue-dashboard",
        "queue-app",
        "app.permissions=queue.read,queue.write\n",
        "api.experimentalCapabilitiesAccepted=false\n",
        "platform.queue.snapshot");
    assertTemplate(
        "publisher",
        "publisher-app",
        "app.permissions=content.insert,queue.read,queue.write\n",
        "api.experimentalCapabilitiesAccepted=false\n",
        "window.CryptaPlatform.content.insertFile");
    assertTemplate(
        "vault-profile",
        "vault-app",
        "app.permissions=vault.identities.read,vault.identities.use\n",
        "api.experimentalCapabilitiesAccepted=true\n",
        "loaded safe mock vault data");
  }

  @Test
  void init_whenUnknownTemplateRequested_expectClearFailure() {
    Path appDir = tempDir.resolve("unknown-template");

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
            "--template",
            "missing-template");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("unsupported app template: missing-template"));
    assertTrue(result.err().contains("queue-dashboard"));
    assertFalse(Files.exists(appDir.resolve("cryptad-app.properties")));
  }

  @Test
  void init_whenStaticTemplateRequestedWithNonStaticMode_expectNoPartialScaffold() {
    Path appDir = tempDir.resolve("bad-template-mode");

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "bad-template-mode",
            "--name",
            "Bad Template Mode",
            "--version",
            "0.1.0",
            "--template",
            "queue-dashboard",
            "--ui-mode",
            "none");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("template queue-dashboard requires --ui-mode static"));
    assertFalse(Files.exists(appDir));
  }

  @Test
  void devServer_whenStaticAppServed_expectBootstrapStaticAndSessionProtectedApi()
      throws Exception {
    Path appDir = scaffold("queue-dashboard", "queue-app");
    Files.writeString(appDir.resolve("cryptad-app.catalog"), "private catalog sidecar");
    Files.writeString(appDir.resolve("cryptad-app.catalog.signature"), "private catalog signature");

    try (CryptaAppDevServer server =
        CryptaAppDevServer.start(
            new DevServerConfig(appDir, "127.0.0.1", 0, null, false, Duration.ofMinutes(10)))) {
      HttpClient client =
          HttpClient.newBuilder()
              .connectTimeout(Duration.ofSeconds(5))
              .version(HttpClient.Version.HTTP_1_1)
              .build();
      HttpResponse<String> bootstrap =
          get(client, server.apiRoot().replace("/api/v1/", "/.well-known/cryptad-bootstrap.json"));
      String sessionToken = sessionToken(bootstrap.body());

      String appRoot = server.apiRoot().replace("/api/v1/", "/apps/queue-app/");
      verifyDevServerBootstrap(bootstrap, server, appDir, sessionToken);
      verifyStaticUiAndMockQueueApi(client, server, sessionToken);
      verifySessionAndStaticSafety(client, server, appRoot, sessionToken);
    }
  }

  @Test
  void devServer_whenEntryIsRootOrNestedDirectory_expectNormalizedAssetRoot() throws Exception {
    HttpClient client =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    Path rootEntryApp = scaffold("static-basic", "root-entry-app");
    Files.move(
        rootEntryApp.resolve("static").resolve("index.html"), rootEntryApp.resolve("index.html"));
    replaceManifestLine(rootEntryApp, "app.ui.entry=static/index.html", "app.ui.entry=index.html");

    try (CryptaAppDevServer server =
        CryptaAppDevServer.start(
            new DevServerConfig(
                rootEntryApp, "127.0.0.1", 0, null, false, Duration.ofMinutes(10)))) {
      String bootstrap =
          get(client, server.apiRoot().replace("/api/v1/", "/.well-known/cryptad-bootstrap.json"))
              .body();

      assertTrue(bootstrap.contains("\"assetRoot\":\"" + server.uiUrl() + "\""));
    }

    Path nestedEntryApp = scaffold("static-basic", "nested-entry-app");
    Path nestedDir = nestedEntryApp.resolve("static").resolve("pages with spaces");
    Files.createDirectories(nestedDir);
    Files.move(
        nestedEntryApp.resolve("static").resolve("index.html"), nestedDir.resolve("index.html"));
    replaceManifestLine(
        nestedEntryApp,
        "app.ui.entry=static/index.html",
        "app.ui.entry=static/pages with spaces/index.html");

    try (CryptaAppDevServer server =
        CryptaAppDevServer.start(
            new DevServerConfig(
                nestedEntryApp, "127.0.0.1", 0, null, false, Duration.ofMinutes(10)))) {
      String appRoot = server.apiRoot().replace("/api/v1/", "/apps/nested-entry-app/");
      String expectedAssetRoot =
          server
              .apiRoot()
              .replace("/api/v1/", "/apps/nested-entry-app/static/pages%20with%20spaces/");
      String bootstrap =
          get(client, server.apiRoot().replace("/api/v1/", "/.well-known/cryptad-bootstrap.json"))
              .body();
      HttpResponse<String> appRootRedirect = get(client, appRoot);
      HttpResponse<String> nestedEntry = get(client, server.uiUrl());

      assertEquals(expectedAssetRoot, server.uiUrl());
      assertTrue(bootstrap.contains("\"assetRoot\":\"" + expectedAssetRoot + "\""));
      assertEquals(302, appRootRedirect.statusCode());
      assertEquals(
          URI.create(expectedAssetRoot).getRawPath(),
          appRootRedirect.headers().firstValue("Location").orElse(""));
      assertEquals(200, nestedEntry.statusCode());
      assertTrue(nestedEntry.body().contains("<title>Nested Entry App</title>"));
    }
  }

  @Test
  void devServer_whenStaticAssetPathContainsSymlinkParent_expectOutsideFileNotServed()
      throws Exception {
    Path appDir = scaffold("static-basic", "symlink-app");
    Path outsideDir = tempDir.resolve("outside-static");
    Files.createDirectories(outsideDir);
    Files.writeString(outsideDir.resolve("secret.txt"), "outside secret", StandardCharsets.UTF_8);
    Path link = appDir.resolve("static").resolve("link");
    try {
      Files.createSymbolicLink(link, outsideDir);
    } catch (IOException | UnsupportedOperationException | SecurityException exception) {
      org.junit.jupiter.api.Assumptions.assumeTrue(
          false, "symlink creation unavailable: " + exception.getMessage());
    }

    try (CryptaAppDevServer server =
        CryptaAppDevServer.start(
            new DevServerConfig(appDir, "127.0.0.1", 0, null, false, Duration.ofMinutes(10)))) {
      HttpClient client =
          HttpClient.newBuilder()
              .connectTimeout(Duration.ofSeconds(5))
              .version(HttpClient.Version.HTTP_1_1)
              .build();
      HttpResponse<String> response = get(client, server.uiUrl() + "link/secret.txt");

      assertEquals(404, response.statusCode());
      assertFalse(response.body().contains("outside secret"));
    }
  }

  @Test
  void test_whenFreshStaticTemplateCheckedStrict_expectPassingHumanAndJsonReport()
      throws Exception {
    Path appDir = scaffold("static-basic", "sample-app");
    Path report = tempDir.resolve("reports").resolve("app-test.json");

    CliResult result =
        runCli("test", "--bundle-dir", appDir.toString(), "--strict", "--json", report.toString());

    String json = Files.readString(report, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("bundle.validate pass"));
    assertTrue(result.out().contains("dev.bootstrap-smoke pass"));
    assertTrue(result.out().contains("App test suite pass: sample-app 0.1.0"));
    assertTrue(json.contains("\"schemaVersion\": 1"));
    assertTrue(json.contains("\"status\": \"pass\""));
    assertTrue(json.contains("\"id\": \"dev.bootstrap-smoke\""));
    assertFalse(json.contains("browserSessionToken"));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void test_whenUiUsesRemoteScript_expectStrictFailureAndRedactedJson() throws Exception {
    Path appDir = scaffold("static-basic", "remote-app");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                "<script src=\"./crypta-platform.js\"></script>",
                "<script src=\"https://cdn.example.invalid/crypta-platform.js\"></script>"),
        StandardCharsets.UTF_8);
    Path report = tempDir.resolve("reports").resolve("remote-test.json");

    CliResult result =
        runCli(
            "test",
            "--bundle-dir",
            appDir.toString(),
            "--strict",
            "--contract",
            tempDir.resolve("missing-contract.json").toString(),
            "--catalog-entry",
            tempDir.resolve("missing-entry.properties").toString(),
            "--json",
            report.toString());

    String json = Files.readString(report, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.out().contains("ui.lint fail"));
    assertTrue(result.out().contains("catalog-entry.sanity fail"));
    assertTrue(json.contains("\"status\": \"fail\""));
    assertTrue(json.contains("[REDACTED_PATH]"));
    assertFalse(json.contains(tempDir.toString()));
    assertFalse(json.contains("browserSessionToken"));
    assertFalse(json.contains("https://cdn.example.invalid/crypta-platform.js"));
  }

  @Test
  void testReportRedactor_whenPathsContainSpaces_expectWholePathRedacted() {
    String redacted =
        AppTestRedactor.redact(
            "missing /Users/alice/My Keys/contract.json and "
                + "C:\\Users\\Alice Keys\\trusted.pem");

    assertTrue(redacted.contains("[REDACTED_PATH]"));
    assertFalse(redacted.contains("My Keys"));
    assertFalse(redacted.contains("Alice Keys"));
    assertFalse(redacted.contains("contract.json"));
    assertFalse(redacted.contains("trusted.pem"));
  }

  @Test
  void keysGenerate_whenUsedForBundleSigning_expectVerifyConsumesTrustedKeysAndNoPrivateOutput()
      throws Exception {
    Path appDir = scaffold("static-basic", "signed-app");
    Path keysDir = tempDir.resolve("keys");
    Path privateKey = keysDir.resolve("dev-local-private.der");
    Path publicKey = keysDir.resolve("dev-local-public.der");
    Path trustedKeys = keysDir.resolve("trusted-app-keys.properties");

    CliResult generate =
        runCli(
            "keys",
            "generate",
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString(),
            "--public-key-file",
            publicKey.toString(),
            "--trusted-keys-file",
            trustedKeys.toString());
    CliResult overwriteFailure =
        runCli(
            "keys",
            "generate",
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString(),
            "--public-key-file",
            publicKey.toString());
    CliResult sign =
        runCli(
            "sign",
            "--bundle-dir",
            appDir.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    CliResult verify =
        runCli(
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--trusted-keys-file",
            trustedKeys.toString());

    assertEquals(CommandLine.ExitCode.OK, generate.exitCode());
    assertTrue(Files.isRegularFile(privateKey));
    assertTrue(Files.isRegularFile(publicKey));
    assertPrivateKeyOwnerOnly(privateKey);
    assertTrue(
        Files.readString(trustedKeys, StandardCharsets.UTF_8).contains("key.0.id=dev-local"));
    assertFalse(generate.out().contains(privateKey.toString()));
    assertFalse(generate.err().contains(privateKey.toString()));
    assertEquals(CommandLine.ExitCode.SOFTWARE, overwriteFailure.exitCode());
    assertTrue(overwriteFailure.err().contains("key output already exists"));
    assertEquals(CommandLine.ExitCode.OK, sign.exitCode());
    assertEquals(CommandLine.ExitCode.OK, verify.exitCode());
    assertTrue(verify.out().contains("Verified bundle:"));
  }

  @Test
  void keysGenerate_whenOutputPathsDuplicate_expectNoPartialKeyMaterial() {
    Path keysDir = tempDir.resolve("duplicate-keys");
    Path duplicate = keysDir.resolve("duplicate.der");
    Path privateKey = keysDir.resolve("private.der");

    CliResult samePrivatePublic =
        runCli(
            "keys",
            "generate",
            "--key-id",
            "dev-local",
            "--private-key-file",
            duplicate.toString(),
            "--public-key-file",
            duplicate.toString());
    CliResult samePublicTrusted =
        runCli(
            "keys",
            "generate",
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString(),
            "--public-key-file",
            duplicate.toString(),
            "--trusted-keys-file",
            duplicate.toString(),
            "--overwrite");

    assertEquals(CommandLine.ExitCode.SOFTWARE, samePrivatePublic.exitCode());
    assertTrue(samePrivatePublic.err().contains("key output paths must be distinct"));
    assertFalse(Files.exists(duplicate));
    assertEquals(CommandLine.ExitCode.SOFTWARE, samePublicTrusted.exitCode());
    assertTrue(samePublicTrusted.err().contains("key output paths must be distinct"));
    assertFalse(Files.exists(privateKey));
    assertFalse(Files.exists(duplicate));
  }

  @Test
  void catalogEntryAndPublishUsk_whenSignedArtifactsPrepared_expectOfflinePlan() throws Exception {
    Path appDir = scaffold("queue-dashboard", "catalog-app");
    Path keysDir = tempDir.resolve("catalog-keys");
    Path privateKey = keysDir.resolve("dev-local-private.der");
    Path publicKey = keysDir.resolve("dev-local-public.der");
    Path trustedKeys = keysDir.resolve("trusted-app-keys.properties");
    Path artifact = tempDir.resolve("catalog-app.zip");
    Path entry = tempDir.resolve("catalog-entry.properties");
    Path catalog = tempDir.resolve("cryptad-app-catalog.properties");
    Path plan = tempDir.resolve("publish-plan.md");

    runCli(
        "keys",
        "generate",
        "--key-id",
        "dev-local",
        "--private-key-file",
        privateKey.toString(),
        "--public-key-file",
        publicKey.toString(),
        "--trusted-keys-file",
        trustedKeys.toString());
    runCli(
        "sign",
        "--bundle-dir",
        appDir.toString(),
        "--key-id",
        "dev-local",
        "--private-key-file",
        privateKey.toString());
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", artifact.toString());

    CliResult entryResult =
        runCli(
            "catalog",
            "entry",
            "--bundle-dir",
            appDir.toString(),
            "--artifact",
            artifact.toString(),
            "--bundle-uri",
            "crypta:CHK@catalog-app-bundle",
            "--output",
            entry.toString(),
            "--summary",
            "Queue dashboard for local development.",
            "--homepage",
            "https://example.invalid/catalog-app",
            "--source",
            "https://example.invalid/catalog-app/source",
            "--license",
            "MIT",
            "--category",
            "Productivity",
            "--permission-rationale",
            "queue.read=Reads mock transfer queue state.",
            "--permission-rationale",
            "queue.write=Exercises mock queue mutation controls.",
            "--strict");
    CliResult create =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalog.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--generated-at",
            "2026-05-14T00:00:00Z",
            "--entry",
            entry.toString());
    CliResult sign =
        runCli(
            "catalog",
            "sign",
            "--catalog-file",
            catalog.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    CliResult verify =
        runCli(
            "catalog",
            "verify",
            "--catalog-file",
            catalog.toString(),
            "--trusted-keys-file",
            trustedKeys.toString());
    Path signature = catalog.resolveSibling("cryptad-app-catalog.signature");
    CliResult publish =
        runCli(
            "publish-usk",
            "--catalog-file",
            catalog.toString(),
            "--catalog-signature-file",
            signature.toString(),
            "--catalog-source",
            "crypta:USK@private-insert-material/cryptad-app-catalog.properties",
            "--output",
            plan.toString(),
            "--dry-run");
    CliResult livePublish =
        runCli(
            "publish-usk",
            "--catalog-file",
            catalog.toString(),
            "--catalog-signature-file",
            signature.toString(),
            "--catalog-source",
            "crypta:USK@private-insert-material/cryptad-app-catalog.properties",
            "--output",
            tempDir.resolve("live-plan.md").toString());

    String descriptor = Files.readString(entry, StandardCharsets.UTF_8);
    String planText = Files.readString(plan, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, entryResult.exitCode());
    assertTrue(descriptor.contains("bundle.uri=crypta:CHK@catalog-app-bundle\n"));
    assertTrue(
        descriptor.contains("permissions.rationale.queue.read=Reads mock transfer queue state.\n"));
    assertEquals(CommandLine.ExitCode.OK, create.exitCode());
    assertEquals(CommandLine.ExitCode.OK, sign.exitCode());
    assertEquals(CommandLine.ExitCode.OK, verify.exitCode());
    assertEquals(CommandLine.ExitCode.OK, publish.exitCode());
    assertTrue(publish.out().contains("Wrote Crypta USK publication plan: dev entries=1"));
    assertTrue(planText.contains("Crypta Catalog USK Publication Plan"));
    assertTrue(planText.contains("crypta:USK@[REDACTED]/cryptad-app-catalog.properties"));
    assertTrue(planText.contains("crypta:CHK@[REDACTED]"));
    assertFalse(planText.contains("private-insert-material"));
    assertFalse(planText.contains(tempDir.toString()));
    assertEquals(CommandLine.ExitCode.SOFTWARE, livePublish.exitCode());
    assertTrue(livePublish.err().contains("live_publish_not_supported"));
  }

  @Test
  void catalogEntryRationales_whenNormalized_expectInsertionOrderPreserved() throws Exception {
    var rationales =
        CatalogEntryDescriptorGenerator.normalizeRationales(
            java.util.List.of("queue.write=Mutates queue.", "queue.read=Reads queue."));

    assertEquals("queue.write,queue.read", String.join(",", rationales.keySet()));
  }

  @Test
  void catalogEntry_whenArtifactPackedBeforeSigning_expectUnsignedArtifactFailure() {
    Path appDir = scaffold("queue-dashboard", "unsigned-catalog-app");
    Path artifact = tempDir.resolve("unsigned-catalog-app.zip");
    Path entry = tempDir.resolve("unsigned-catalog-entry.properties");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", artifact.toString());

    CliResult result =
        runCli(
            "catalog",
            "entry",
            "--bundle-dir",
            appDir.toString(),
            "--artifact",
            artifact.toString(),
            "--bundle-uri",
            "crypta:CHK@unsigned-catalog-app-bundle",
            "--output",
            entry.toString(),
            "--summary",
            "Unsigned artifact check.");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("zip artifact must contain signed bundle sidecars"));
    assertFalse(Files.exists(entry));
  }

  @Test
  void catalogEntry_whenBundleManifestChangedAfterPacking_expectArtifactMismatchFailure()
      throws Exception {
    Path appDir = scaffold("queue-dashboard", "stale-catalog-app");
    Path keysDir = tempDir.resolve("stale-catalog-keys");
    Path privateKey = keysDir.resolve("dev-local-private.der");
    Path publicKey = keysDir.resolve("dev-local-public.der");
    Path artifact = tempDir.resolve("stale-catalog-app.zip");
    Path entry = tempDir.resolve("stale-catalog-entry.properties");
    runCli(
        "keys",
        "generate",
        "--key-id",
        "dev-local",
        "--private-key-file",
        privateKey.toString(),
        "--public-key-file",
        publicKey.toString());
    runCli(
        "sign",
        "--bundle-dir",
        appDir.toString(),
        "--key-id",
        "dev-local",
        "--private-key-file",
        privateKey.toString());
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", artifact.toString());
    replaceManifestLine(
        appDir, "app.permissions=queue.read,queue.write", "app.permissions=queue.read");

    CliResult result =
        runCli(
            "catalog",
            "entry",
            "--bundle-dir",
            appDir.toString(),
            "--artifact",
            artifact.toString(),
            "--bundle-uri",
            "crypta:CHK@stale-catalog-app-bundle",
            "--output",
            entry.toString(),
            "--summary",
            "Stale catalog metadata check.");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("bundle manifest must match artifact manifest"));
    assertFalse(Files.exists(entry));
  }

  @Test
  void help_whenRequested_expectDeveloperBetaToolkitCommandsExposed() {
    CliResult root = runCli("--help");
    CliResult catalog = runCli("catalog");

    assertEquals(CommandLine.ExitCode.OK, root.exitCode());
    assertTrue(root.out().contains("dev"));
    assertTrue(root.out().contains("test"));
    assertTrue(root.out().contains("keys"));
    assertTrue(root.out().contains("publish-usk"));
    assertEquals(CommandLine.ExitCode.OK, catalog.exitCode());
    assertTrue(catalog.out().contains("entry"));
  }

  private void assertTemplate(
      String template,
      String appId,
      String expectedPermissionsLine,
      String expectedExperimentalLine,
      String expectedScript)
      throws Exception {
    Path appDir = scaffold(template, appId);
    CliResult test = runCli("test", "--bundle-dir", appDir.toString(), "--strict");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);
    String index =
        Files.readString(appDir.resolve("static").resolve("index.html"), StandardCharsets.UTF_8);
    String script =
        Files.readString(appDir.resolve("static").resolve("app.js"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, test.exitCode(), test.err());
    assertTrue(manifest.contains(expectedPermissionsLine));
    assertTrue(manifest.contains(expectedExperimentalLine));
    assertTrue(index.contains("data-crypta-permission-summary"));
    assertTrue(script.contains(expectedScript));
    if ("queue-dashboard".equals(template)) {
      assertTrue(script.contains("form.set(\"priority\", \"2\");"));
    }
    if ("publisher".equals(template)) {
      assertTrue(index.contains("name=\"sourcePath\""));
      assertTrue(index.contains("name=\"insertUri\""));
      assertTrue(index.contains("name=\"identifier\""));
      assertTrue(script.contains("params.set(\"sourcePath\""));
      assertTrue(script.contains("params.set(\"insertUri\""));
      assertTrue(script.contains("params.set(\"identifier\""));
      assertFalse(script.contains("params.set(\"content\""));
      assertFalse(script.contains("params.set(\"target\""));
    }
    assertFalse(index.contains("https://"));
    assertFalse(index.contains("http://"));
    assertFalse(script.contains("https://"));
    assertFalse(script.contains("http://"));
    assertFalse(script.contains("vault.secrets"));
    assertFalse(script.toLowerCase(java.util.Locale.ROOT).contains("seed phrase"));
  }

  private Path scaffold(String template, String appId) {
    Path appDir = tempDir.resolve(appId);
    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            appId,
            "--name",
            titleCase(appId),
            "--version",
            "0.1.0",
            "--template",
            template);
    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    return appDir;
  }

  private static void verifyDevServerBootstrap(
      HttpResponse<String> bootstrap, CryptaAppDevServer server, Path appDir, String sessionToken) {
    assertEquals(200, bootstrap.statusCode());
    assertTrue(bootstrap.body().contains("\"appId\":\"queue-app\""));
    assertTrue(bootstrap.body().contains("\"platformApiRoot\":\"" + server.apiRoot()));
    assertFalse(server.startupSummary().contains(sessionToken));
    assertFalse(server.startupSummary().contains(appDir.toString()));
  }

  private static void verifyStaticUiAndMockQueueApi(
      HttpClient client, CryptaAppDevServer server, String sessionToken) throws Exception {
    HttpResponse<String> staticUi = get(client, server.uiUrl());
    HttpResponse<String> tokenStylesheet =
        get(client, server.uiUrl() + "crypta-ui/crypta-ui-tokens.css");
    HttpResponse<String> api =
        getWithSession(client, URI.create(server.apiRoot() + "queue"), sessionToken);
    HttpResponse<String> missingPriority =
        postFormWithSession(
            client,
            URI.create(server.apiRoot() + "queue/requests/priority"),
            sessionToken,
            "identifier=mock-download-1");
    HttpResponse<String> priorityMutation =
        postFormWithSession(
            client,
            URI.create(server.apiRoot() + "queue/requests/priority"),
            sessionToken,
            "identifier=mock-download-1&priority=2");
    HttpResponse<String> missingInsertField =
        postFormWithSession(
            client,
            URI.create(server.apiRoot() + "queue/inserts/file"),
            sessionToken,
            "sourcePath=sample.txt&identifier=sample-insert");
    HttpResponse<String> fileInsert =
        postFormWithSession(
            client,
            URI.create(server.apiRoot() + "queue/inserts/file"),
            sessionToken,
            "sourcePath=sample.txt&insertUri=CHK%40sample&identifier=sample-insert");

    assertEquals(200, staticUi.statusCode());
    assertTrue(staticUi.body().contains("<title>Queue App</title>"));
    assertEquals(200, tokenStylesheet.statusCode());
    assertTrue(
        tokenStylesheet.headers().firstValue("Content-Type").orElse("").startsWith("text/css"));
    assertEquals(200, api.statusCode());
    assertTrue(api.body().contains("mock-download-1"));
    assertEquals(400, missingPriority.statusCode());
    assertTrue(missingPriority.body().contains("invalid_mock_form"));
    assertEquals(200, priorityMutation.statusCode());
    assertTrue(priorityMutation.body().contains("queue.requests.priority"));
    assertEquals(400, missingInsertField.statusCode());
    assertTrue(missingInsertField.body().contains("insertUri"));
    assertEquals(200, fileInsert.statusCode());
    assertTrue(fileInsert.body().contains("queue.inserts.file"));
  }

  private static void verifySessionAndStaticSafety(
      HttpClient client, CryptaAppDevServer server, String appRoot, String sessionToken)
      throws Exception {
    HttpResponse<String> missingSession = get(client, server.apiRoot() + "queue");
    HttpResponse<String> wrongSession =
        getWithSession(client, URI.create(server.apiRoot() + "queue"), "wrong-session");
    HttpResponse<String> unsafeManifest = get(client, appRoot + "%2e%2e/cryptad-app.properties");
    HttpResponse<String> encodedSeparator = get(client, appRoot + "static%2Findex.html");
    HttpResponse<String> appRootRedirect = get(client, appRoot);
    HttpResponse<String> reservedManifest = get(client, appRoot + "cryptad-app.properties");
    HttpResponse<String> reservedManifestCaseVariant =
        get(client, appRoot + "CRYPTAD-APP.PROPERTIES");
    HttpResponse<String> reservedCatalog = get(client, appRoot + "cryptad-app.catalog");
    HttpResponse<String> reservedCatalogSignature =
        get(client, appRoot + "cryptad-app.catalog.signature");

    assertEquals(401, missingSession.statusCode());
    assertTrue(missingSession.body().contains("invalid_app_browser_session"));
    assertEquals(401, wrongSession.statusCode());
    assertTrue(wrongSession.body().contains("invalid_app_browser_session"));
    assertEquals(400, unsafeManifest.statusCode());
    assertEquals(400, encodedSeparator.statusCode());
    assertEquals(302, appRootRedirect.statusCode());
    assertEquals(
        URI.create(server.uiUrl()).getRawPath(),
        appRootRedirect.headers().firstValue("Location").orElse(""));
    assertEquals(400, reservedManifest.statusCode());
    assertEquals(400, reservedManifestCaseVariant.statusCode());
    assertEquals(400, reservedCatalog.statusCode());
    assertEquals(400, reservedCatalogSignature.statusCode());
    assertFalse(missingSession.body().contains(sessionToken));
    assertFalse(wrongSession.body().contains("wrong-session"));
  }

  private static String titleCase(String appId) {
    StringBuilder builder = new StringBuilder(appId.length());
    boolean capitalize = true;
    for (int index = 0; index < appId.length(); index++) {
      char character = appId.charAt(index);
      if (character == '-') {
        builder.append(' ');
        capitalize = true;
      } else if (capitalize) {
        builder.append(Character.toUpperCase(character));
        capitalize = false;
      } else {
        builder.append(character);
      }
    }
    return builder.toString();
  }

  private static HttpResponse<String> get(HttpClient client, String uri) throws Exception {
    return get(client, URI.create(uri));
  }

  private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
    return client.send(
        HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private static HttpResponse<String> getWithSession(HttpClient client, URI uri, String session)
      throws Exception {
    return client.send(
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(5))
            .header("X-Crypta-App-Session", session)
            .GET()
            .build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private static HttpResponse<String> postFormWithSession(
      HttpClient client, URI uri, String session, String body) throws Exception {
    return client.send(
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(5))
            .header("X-Crypta-App-Session", session)
            .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(),
        HttpResponse.BodyHandlers.ofString());
  }

  private static void replaceManifestLine(Path appDir, String currentLine, String replacementLine)
      throws Exception {
    Path manifest = appDir.resolve("cryptad-app.properties");
    String text = Files.readString(manifest, StandardCharsets.UTF_8);
    Files.writeString(manifest, text.replace(currentLine, replacementLine), StandardCharsets.UTF_8);
  }

  private static void assertPrivateKeyOwnerOnly(Path privateKey) throws Exception {
    try {
      assertEquals(
          Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
          Files.getPosixFilePermissions(privateKey));
    } catch (UnsupportedOperationException _) {
      assertTrue(privateKey.toFile().canRead());
      assertTrue(privateKey.toFile().canWrite());
    }
  }

  private static String sessionToken(String bootstrapJson) {
    Matcher matcher = BOOTSTRAP_SESSION_PATTERN.matcher(bootstrapJson);
    if (!matcher.find()) {
      throw new AssertionError("bootstrap did not include a browser session token");
    }
    return matcher.group(1);
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
