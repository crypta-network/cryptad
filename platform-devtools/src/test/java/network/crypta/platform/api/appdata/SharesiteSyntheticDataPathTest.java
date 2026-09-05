package network.crypta.platform.api.appdata;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.platform.devtools.CryptaAppCli;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Executable SYNTHETIC data-path demonstration with the pinned writer fixture and real signed host.
 * No catalog authority, real user snapshot, managed-node observation, or network publication is
 * claimed. The ephemeral test signing key never enters the migration payload.
 */
class SharesiteSyntheticDataPathTest {
  private static final String APP = "site-publisher";
  private static final String NAMESPACE = "sharesite-drafts";
  private static final String OPERATION = "c2de6c66-411f-4d65-a94e-4e78b63368de";
  private static final String LITERAL = "<script>inert</script>\r\nα\n🙂\r";
  @TempDir Path temporary;

  @Test
  void
      syntheticMigration_whenConvertedIntoVerifiedInstalledApp_expectDurableFidelityAndSeparateRecovery()
          throws Exception {
    // Arrange the exact upstream-writer synthetic binary and real offline CLI outputs.
    byte[] sourceBytes;
    try (var source =
        getClass()
            .getResourceAsStream(
                "/network/crypta/platform/devtools/migration/sharesite/upstream-mixed.db")) {
      assertNotNull(source);
      sourceBytes = source.readAllBytes();
    }
    Path source = temporary.resolve("Sharesite.db");
    Files.write(source, sourceBytes);
    Path workspace = temporary.resolve("private-operation");
    StringWriter diagnostics = new StringWriter();
    assertEquals(0, cli(diagnostics, source, workspace, "inspect", List.of()));
    List<String> selection =
        List.of(
            "--select",
            "0",
            "--operation-id",
            OPERATION,
            "--provenance",
            "SYNTHETIC pinned-writer stopped snapshot",
            "--ack-exclusions");
    assertEquals(0, cli(diagnostics, source, workspace, "plan", selection));
    String planDigest = digest(Files.readAllBytes(workspace.resolve("plan.json")));
    var exportArguments = new ArrayList<>(selection);
    exportArguments.addAll(List.of("--ack-plan-sha256", planDigest));
    assertEquals(0, cli(diagnostics, source, workspace, "export", exportArguments));
    byte[] migrationBytes = Files.readAllBytes(workspace.resolve("migration.json"));
    Map<String, Object> wrapper = object(migrationBytes);
    AppDataExportPayload converted = AppDataExportPayload.parse(json(wrapper.get("payload")));
    Map<String, Object> proposed = assertConvertedPayload(wrapper, converted);
    List<Map<String, Object>> drafts = rows(proposed, "drafts");

    // The owning app derives a ledger from the verified converted drafts, as its UI does.
    Map<String, Object> operation =
        Map.of(
            "operationId",
            OPERATION,
            "payloadSha256",
            digest(migrationBytes),
            "status",
            "committed",
            "draftIds",
            List.of(drafts.getFirst().get("id")),
            "originalsSha256",
            SharesiteDraftWriteGuard.canonicalDigest(drafts));
    proposed.put("operations", List.of(operation));
    KeyPair signer =
        KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    LocalProcessAppHost host = host(signer);
    Path currentBundle = signedBundle("3.1", signer);
    host.installFromDirectory(currentBundle);
    var authentication = host.withVerifiedInstalledBundle(APP, (_, verification) -> verification);
    assertTrue(authentication.signed());
    assertEquals("3.1", host.describe(APP).orElseThrow().manifest().appVersion());
    Path storePath = temporary.resolve("durable-store");
    AppDataService service = service(host, storePath);
    service.putRecord(
        APP,
        Map.of(
            "namespace",
            List.of("unrelated"),
            "key",
            List.of("draft"),
            "schemaVersion",
            List.of("1"),
            "valueText",
            List.of("preexisting unrelated draft")));
    Map<String, List<String>> request = request(proposed, "import", "absent");

    // Act: actual guarded preview and atomic durable commit, then reconstruct host and store.
    Map<String, Object> preview = service.putRecord(APP, request);
    assertFalse(
        Files.readString(workspace.resolve("inspection.json"))
            .contains("SYNTHETIC_SECRET_CANARY_DO_NOT_EXPORT"));
    assertFalse(PlatformApiJsonWriter.write(preview).contains(LITERAL));
    assertEquals(1, service.status(APP).get("recordCount"));
    Map<String, Object> committed = commit(service, request, preview);
    String committedDigest = (String) committed.get("sha256");
    host = host(signer);
    service = service(host, storePath);
    assertEquals(committed, service.getRecord(APP, NAMESPACE, "dataset"));
    assertEquals(
        "preexisting unrelated draft",
        service.getRecord(APP, "unrelated", "draft").get("valueText"));
    assertEquals(
        LITERAL,
        rows(
                object(((String) committed.get("valueText")).getBytes(StandardCharsets.UTF_8)),
                "drafts")
            .getFirst()
            .get("text"));

    // Exact replay is detected by the durable app ledger and requires no mutation or publication.
    assertEquals(
        digest(migrationBytes),
        rows(
                object(((String) committed.get("valueText")).getBytes(StandardCharsets.UTF_8)),
                "operations")
            .getFirst()
            .get("payloadSha256"));
    assertEquals(committedDigest, service.getRecord(APP, NAMESPACE, "dataset").get("sha256"));

    AppDataExportPayload backup =
        assertIndependentRecovery(
            host,
            signer,
            service,
            committed,
            operation,
            authentication.signedContentDigestSha256());
    assertArrayEquals(sourceBytes, Files.readAllBytes(source));
    assertFalse(diagnostics.toString().contains(source.toString()));
    assertFalse(diagnostics.toString().contains("SYNTHETIC_SECRET_CANARY_DO_NOT_EXPORT"));
    assertFalse(
        new String(backup.toJsonBytes(), StandardCharsets.UTF_8)
            .contains("SYNTHETIC_SECRET_CANARY_DO_NOT_EXPORT"));
  }

  private static Map<String, Object> assertConvertedPayload(
      Map<String, Object> wrapper, AppDataExportPayload converted) {
    assertEquals(APP, converted.appId());
    assertEquals(1, converted.records().size());
    assertEquals(NAMESPACE, converted.records().getFirst().namespace());
    Map<String, Object> proposed = object(converted.records().getFirst().value());
    List<Map<String, Object>> drafts = rows(proposed, "drafts");
    assertEquals(LITERAL, drafts.getFirst().get("text"));
    assertEquals("Synthetic page 0", drafts.getFirst().get("logicalPath"));
    assertTrue(rows(proposed, "operations").isEmpty());
    Map<?, ?> lineage = (Map<?, ?>) wrapper.get("source");
    assertEquals(
        digest(LITERAL.getBytes(StandardCharsets.UTF_8)),
        ((Map<?, ?>) lineage.get("literalTextSha256")).get("0"));
    return proposed;
  }

  private AppDataExportPayload assertIndependentRecovery(
      LocalProcessAppHost host,
      KeyPair signer,
      AppDataService service,
      Map<String, Object> committed,
      Map<String, Object> operation,
      String signedContentDigest)
      throws IOException {
    String committedDigest = (String) committed.get("sha256");
    // A private app export is parsed back through the existing interchange representation.
    var privateBackup = service.exportData(APP, Map.of("namespace", List.of(NAMESPACE)));
    AppDataExportPayload backup =
        AppDataExportPayload.parse(
            Base64.getUrlDecoder().decode((String) privateBackup.get("payloadBase64")));
    assertEquals(
        LITERAL,
        rows(object(backup.records().getFirst().value()), "drafts").getFirst().get("text"));

    // Local data undo has its own operation outcome, retaining the durable operation tombstone.
    var undoneOperation = new LinkedHashMap<>(operation);
    undoneOperation.put("status", "undone");
    Map<String, Object> undone =
        Map.of("schemaVersion", 1, "operations", List.of(undoneOperation), "drafts", List.of());
    var undoResult = apply(service, undone, "undo", committedDigest);
    assertTrue(
        rows(
                object(((String) undoResult.get("valueText")).getBytes(StandardCharsets.UTF_8)),
                "drafts")
            .isEmpty());
    assertEquals(
        "preexisting unrelated draft",
        service.getRecord(APP, "unrelated", "draft").get("valueText"));

    // Recovery restores the private export into isolated empty app data, then preserves later
    // edits.
    AppDataService recovered = service(host, temporary.resolve("private-recovery-store"));
    var restored =
        apply(recovered, object(backup.records().getFirst().value()), "restore", "absent");
    assertEquals(committed.get("valueText"), restored.get("valueText"));
    Map<String, Object> edited = object(backup.records().getFirst().value());
    rows(edited, "drafts").getFirst().put("text", "edited literal <img src=x onerror=alert(1)>");
    var saved = apply(recovered, edited, "edit", (String) restored.get("sha256"));
    var undoRequest = request(undone, "undo", (String) saved.get("sha256"));
    assertEquals(
        "sharesite_undo_requires_manual_recovery",
        assertThrows(PlatformApiException.class, () -> recovered.putRecord(APP, undoRequest))
            .errorCode());

    // Signed app bundle update/rollback is independently verified and does not roll back drafts.
    host.updateFromDirectory(APP, signedBundle("3.2", signer));
    assertEquals("3.2", host.describe(APP).orElseThrow().manifest().appVersion());
    host.rollback(APP);
    assertEquals("3.1", host.describe(APP).orElseThrow().manifest().appVersion());
    assertEquals(
        signedContentDigest,
        host.withVerifiedInstalledBundle(
            APP, (_, verification) -> verification.signedContentDigestSha256()));
    assertEquals(saved, recovered.getRecord(APP, NAMESPACE, "dataset"));
    return backup;
  }

  private LocalProcessAppHost host(KeyPair signer) {
    TrustedAppKeys keys =
        TrustedAppKeys.of(
            new TrustedAppKey(
                "synthetic-migration-only",
                AppBundleSignature.SIGNATURE_ALGORITHM,
                signer.getPublic()));
    AppBundleVerifier current = AppBundleVerifier.requireSigned(keys);
    AppBundleVerifier historical = AppBundleVerifier.requireSignedForHistoricalVerification(keys);
    return new LocalProcessAppHost(
        new AppHostLayout(
            temporary.resolve("host-data"),
            temporary.resolve("host-cache"),
            temporary.resolve("host-run")),
        AppInstallVerificationPolicy.requireSignedWithIdentity(
            current::verify, historical::verify));
  }

  private Path signedBundle(String version, KeyPair signer) throws IOException {
    Path staged = Path.of(System.getProperty("sharesite.synthetic.sitePublisherBundle"));
    Path copy = temporary.resolve("synthetic-bundle-" + version);
    try (var paths = Files.walk(staged)) {
      for (Path input : paths.toList()) {
        Path output = copy.resolve(staged.relativize(input));
        if (Files.isDirectory(input)) Files.createDirectories(output);
        else Files.copy(input, output);
      }
    }
    Path manifest = copy.resolve("cryptad-app.properties");
    Files.writeString(
        manifest, Files.readString(manifest).replace("app.version=3.1", "app.version=" + version));
    AppBundleSigner.sign(copy, "synthetic-migration-only", signer.getPrivate());
    return copy;
  }

  private static AppDataService service(LocalProcessAppHost host, Path store) {
    return new AppDataService(
        new FileAppDataStore(store, AppDataStoreConfig.defaults()),
        host,
        AppDataStoreConfig.defaults(),
        Clock.fixed(Instant.parse("2026-09-05T12:00:00Z"), ZoneOffset.UTC),
        new AppDiskUsageScanner(),
        true);
  }

  private static int cli(
      StringWriter diagnostics, Path source, Path workspace, String action, List<String> extra) {
    List<String> args =
        new ArrayList<>(
            List.of(
                "migration",
                "sharesite",
                action,
                "--snapshot",
                source.toString(),
                "--workspace",
                workspace.toString(),
                "--writer-stopped"));
    args.addAll(extra);
    return new CommandLine(new CryptaAppCli())
        .setOut(new PrintWriter(diagnostics))
        .setErr(new PrintWriter(diagnostics))
        .execute(args.toArray(String[]::new));
  }

  private static Map<String, List<String>> request(
      Map<String, Object> data, String mode, String current) {
    return new LinkedHashMap<>(
        Map.of(
            "namespace",
            List.of(NAMESPACE),
            "key",
            List.of("dataset"),
            "schemaVersion",
            List.of("1"),
            "valueJson",
            List.of(PlatformApiJsonWriter.write(data)),
            "ifMatchSha256",
            List.of(current),
            "writeIntent",
            List.of("preview"),
            "writeMode",
            List.of(mode),
            "backupReady",
            List.of("true")));
  }

  private static Map<String, Object> commit(
      AppDataService service, Map<String, List<String>> request, Map<String, Object> preview) {
    var commit = new LinkedHashMap<>(request);
    commit.put("writeIntent", List.of("commit"));
    commit.put("writePreviewId", List.of((String) preview.get("previewId")));
    return service.putRecord(APP, commit);
  }

  private static Map<String, Object> apply(
      AppDataService service, Map<String, Object> data, String mode, String current) {
    var request = request(data, mode, current);
    return commit(service, request, service.putRecord(APP, request));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(byte[] json) {
    return (Map<String, Object>) AppDataJsonParser.parse(new String(json, StandardCharsets.UTF_8));
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> rows(Map<String, Object> data, String field) {
    return (List<Map<String, Object>>) data.get(field);
  }

  private static byte[] json(Object value) {
    return PlatformApiJsonWriter.write(value).getBytes(StandardCharsets.UTF_8);
  }

  private static String digest(byte[] bytes) {
    try {
      return java.util.HexFormat.of()
          .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (java.security.NoSuchAlgorithmException impossible) {
      throw new AssertionError(impossible);
    }
  }
}
