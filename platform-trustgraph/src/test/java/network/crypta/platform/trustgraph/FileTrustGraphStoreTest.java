package network.crypta.platform.trustgraph;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileTrustGraphStoreTest {
  private static final Instant NOW = Instant.parse("2026-05-17T00:00:00Z");

  @TempDir private java.nio.file.Path tempDir;

  @Test
  void reopen_whenAnchorStored_expectAnchorDurable() {
    FileTrustGraphStore store = store();
    store.addAnchor(new TrustAnchor("fingerprint-1", "Alice", "manual", NOW));

    FileTrustGraphStore reopened = store();

    assertEquals(1, reopened.anchors().size());
    assertEquals("fingerprint-1", reopened.anchors().getFirst().issuerFingerprint());
    assertTrue(reopened.durable());
    assertEquals("file", reopened.storeType());
  }

  @Test
  void reopen_whenVerifiedStatementAndAnchorStored_expectScoreUsesDurableState() throws Exception {
    TrustStatementDocument document = signedStatement(80, 50);
    FileTrustGraphStore store = store();
    store.addAnchor(new TrustAnchor(fingerprint(document), "Alice", "manual", NOW));
    store.importStatement(document, "fetched", "crypta:CHK@trust-statement", "fixture");

    FileTrustGraphStore reopened = store();
    TrustGraphScore score =
        new TrustGraphScorer(reopened, Clock.fixed(NOW, ZoneOffset.UTC)).score(query());

    assertEquals(1, reopened.statementCount());
    assertEquals("trusted", score.status());
    assertEquals(80, score.score());
    assertEquals(1, score.contributingEvidenceCount());
    assertTrue(reopened.statements().getFirst().sourceUri().startsWith("CHK@sha256:"));
    assertEquals(64, reopened.statements().getFirst().sourceUriHash().length());
    assertFalse(reopened.statements().getFirst().sourceUri().contains("trust-statement"));
    assertFalse(allRelativePaths().contains("CHK@trust-statement"));
  }

  @Test
  void importStatement_whenSameDocumentImportedTwice_expectMetadataReplacedWithoutDuplicate()
      throws Exception {
    FileTrustGraphStore store = store();
    TrustStatementDocument document = signedStatement(40, 60);

    TrustGraphImportResult first = store.importStatement(document, "manual", null, "first");
    TrustGraphImportResult second =
        store.importStatement(document, "content-fetch", null, "second");
    FileTrustGraphStore reopened = store();

    assertTrue(first.imported());
    assertFalse(second.imported());
    assertEquals(1, store.statementCount());
    assertEquals(1, reopened.statementCount());
    assertEquals("content-fetch", reopened.statements().getFirst().source());
    assertEquals("second", reopened.statements().getFirst().sourceLabel());
  }

  @Test
  void reopen_whenStatementRevokedAndReimported_expectLifecycleDurableAndPreserved()
      throws Exception {
    FileTrustGraphStore store = store();
    TrustStatementDocument document = signedStatement(40, 60);
    TrustGraphImportResult imported = store.importStatement(document, "manual", null, "first");

    TrustStatementLifecycleRecord revoked =
        store.updateLifecycle(
            imported.documentFingerprint(),
            TrustStatementLifecycleStatus.REVOKED,
            "operator-revoked",
            "local note",
            "crypta:CHK@replacement",
            "trust-graph",
            "app");
    TrustGraphImportResult reimported =
        store.importStatement(document, "content-fetch", null, "second");
    FileTrustGraphStore reopened = store();

    assertEquals(TrustStatementLifecycleStatus.REVOKED, revoked.status());
    assertFalse(reimported.imported());
    assertEquals(1, reopened.statementCount());
    assertEquals(
        TrustStatementLifecycleStatus.REVOKED,
        reopened.lifecycle(imported.documentFingerprint()).status());
    assertEquals(
        "operator-revoked", reopened.lifecycle(imported.documentFingerprint()).reasonCode());
    assertTrue(
        reopened
            .lifecycle(imported.documentFingerprint())
            .replacementUri()
            .startsWith("CHK@sha256:"));
    assertEquals(
        "revoked",
        reopened
            .statements()
            .getFirst()
            .toSummaryJson(reopened.lifecycle(imported.documentFingerprint()))
            .get("lifecycleStatus"));
    assertFalse(allRelativePaths().contains("CHK@replacement"));
  }

  @Test
  void addAnchor_whenExistingAnchorReplacedAtLimit_expectNoUnrelatedEviction() {
    FileTrustGraphStore store = store(new TrustGraphStoreConfig(4, 2, 4, 65_536));
    store.addAnchor(new TrustAnchor("fingerprint-1", "Original", "manual", NOW));
    store.addAnchor(new TrustAnchor("fingerprint-2", "Other", "manual", NOW.plusSeconds(1)));

    store.addAnchor(new TrustAnchor("fingerprint-1", "Updated", "profile", NOW.plusSeconds(2)));

    List<String> retained = store.anchors().stream().map(TrustAnchor::issuerFingerprint).toList();
    assertEquals(List.of("fingerprint-1", "fingerprint-2"), retained);
    assertEquals("Updated", store.anchors().getFirst().label());
  }

  @Test
  void removeAnchor_whenPersistedAnchorCannotBeDeleted_expectStoreUnavailableAndAnchorRetained()
      throws Exception {
    FileTrustGraphStore store = store();
    store.addAnchor(new TrustAnchor("fingerprint-delete", "Delete Me", "manual", NOW));
    java.nio.file.Path anchorFile = firstAnchorRecord();
    java.nio.file.Files.delete(anchorFile);
    java.nio.file.Files.createDirectory(anchorFile);
    java.nio.file.Files.writeString(anchorFile.resolve("child"), "keeps directory non-empty");

    TrustGraphException exception =
        assertThrows(TrustGraphException.class, () -> store.removeAnchor("fingerprint-delete"));

    assertEquals("trust_graph_store_unavailable", exception.errorCode());
    assertEquals(List.of("fingerprint-delete"), retainedAnchors(store));
  }

  @Test
  void open_whenRootDirectoryIsSymbolicLink_expectStoreUnavailable() throws Exception {
    java.nio.file.Path outside = tempDir.resolve("outside-root");
    java.nio.file.Files.createDirectory(outside);
    java.nio.file.Path rootLink = tempDir.resolve("trust-root-link");
    createSymbolicLinkOrSkip(rootLink, outside);

    TrustGraphException exception =
        assertThrows(TrustGraphException.class, () -> openStore(rootLink));

    assertEquals("trust_graph_store_unavailable", exception.errorCode());
  }

  @Test
  void open_whenManagedAncestorDirectoryIsSymbolicLink_expectStoreUnavailable() throws Exception {
    java.nio.file.Path dataRoot = tempDir.resolve("data");
    java.nio.file.Files.createDirectory(dataRoot);
    java.nio.file.Path outsideApps = tempDir.resolve("outside-apps");
    java.nio.file.Files.createDirectory(outsideApps);
    java.nio.file.Path appsLink = dataRoot.resolve("apps");
    createSymbolicLinkOrSkip(appsLink, outsideApps);
    java.nio.file.Path root = appsLink.resolve("trust-graph");

    TrustGraphException exception =
        assertThrows(TrustGraphException.class, () -> openStore(root, dataRoot));

    assertEquals("trust_graph_store_unavailable", exception.errorCode());
  }

  @Test
  void open_whenManagedChildDirectoryIsSymbolicLink_expectStoreUnavailable() throws Exception {
    java.nio.file.Path root = tempDir.resolve("trust-root");
    java.nio.file.Files.createDirectory(root);
    java.nio.file.Path outsideAnchors = tempDir.resolve("outside-anchors");
    java.nio.file.Files.createDirectory(outsideAnchors);
    createSymbolicLinkOrSkip(root.resolve("anchors"), outsideAnchors);

    TrustGraphException exception = assertThrows(TrustGraphException.class, () -> openStore(root));

    assertEquals("trust_graph_store_unavailable", exception.errorCode());
  }

  @Test
  void addAnchor_whenAnchorDirectoryReplacedWithSymbolicLink_expectStoreUnavailable()
      throws Exception {
    FileTrustGraphStore store = store();
    java.nio.file.Files.delete(tempDir.resolve("anchors"));
    java.nio.file.Path outsideAnchors = tempDir.resolve("outside-replaced-anchors");
    java.nio.file.Files.createDirectory(outsideAnchors);
    createSymbolicLinkOrSkip(tempDir.resolve("anchors"), outsideAnchors);
    TrustAnchor anchor = new TrustAnchor("fingerprint-link", "Link", "manual", NOW);

    TrustGraphException exception =
        assertThrows(TrustGraphException.class, () -> store.addAnchor(anchor));

    assertEquals("trust_graph_store_unavailable", exception.errorCode());
    assertTrue(store.anchors().isEmpty());
  }

  @Test
  void removeAnchor_whenAnchorDirectoryReplacedWithSymbolicLink_expectStoreUnavailableAndRetained()
      throws Exception {
    FileTrustGraphStore store = store();
    store.addAnchor(new TrustAnchor("fingerprint-link-delete", "Link Delete", "manual", NOW));
    java.nio.file.Path anchorsDirectory = tempDir.resolve("anchors");
    try (var stream = java.nio.file.Files.list(anchorsDirectory)) {
      for (java.nio.file.Path path : stream.toList()) {
        java.nio.file.Files.delete(path);
      }
    }
    java.nio.file.Files.delete(anchorsDirectory);
    java.nio.file.Path outsideAnchors = tempDir.resolve("outside-remove-anchors");
    java.nio.file.Files.createDirectory(outsideAnchors);
    createSymbolicLinkOrSkip(anchorsDirectory, outsideAnchors);

    TrustGraphException exception =
        assertThrows(
            TrustGraphException.class, () -> store.removeAnchor("fingerprint-link-delete"));

    assertEquals("trust_graph_store_unavailable", exception.errorCode());
    assertEquals(List.of("fingerprint-link-delete"), retainedAnchors(store));
  }

  @Test
  void retention_whenCapsExceeded_expectOldestRecordsEvicted() throws Exception {
    FileTrustGraphStore store = store(new TrustGraphStoreConfig(2, 2, 2, 65_536));
    TrustStatementDocument first = signedStatement(10, 10);
    TrustStatementDocument second = signedStatement(20, 20);
    TrustStatementDocument third = signedStatement(30, 30);

    store.importStatement(first, "manual", null, null);
    store.importStatement(second, "manual", null, null);
    store.importStatement(third, "manual", null, null);
    store.addAnchor(new TrustAnchor("fingerprint-1", "One", "manual", NOW));
    store.addAnchor(new TrustAnchor("fingerprint-2", "Two", "manual", NOW.plusSeconds(1)));
    store.addAnchor(new TrustAnchor("fingerprint-3", "Three", "manual", NOW.plusSeconds(2)));

    FileTrustGraphStore reopened = store(new TrustGraphStoreConfig(2, 2, 2, 65_536));

    assertEquals(2, reopened.statementCount());
    assertFalse(
        reopened.statements().stream()
            .map(TrustGraphStore.StoredTrustStatement::documentFingerprint)
            .toList()
            .contains(TrustStatementFingerprint.documentFingerprint(first)));
    assertEquals(List.of("fingerprint-2", "fingerprint-3"), retainedAnchors(reopened));
  }

  @Test
  void reopen_whenPersistedRecordIsCorrupt_expectRecordIgnoredSafely() throws Exception {
    java.nio.file.Files.createDirectories(tempDir.resolve("statements"));
    java.nio.file.Files.writeString(
        tempDir.resolve("statements").resolve("corrupt.properties"),
        "version=1\ndocumentFingerprint=fixture\ndocumentJson={not-json\n");

    FileTrustGraphStore reopened = store();

    assertEquals(0, reopened.statementCount());
  }

  @Test
  void auditEvents_whenStoredAndReopened_expectBoundedNewestFirstAndRedacted() {
    FileTrustGraphStore store = store(new TrustGraphStoreConfig(4, 4, 2, 65_536));
    store.appendAuditEvent(event("statement_imported", NOW, "first"));
    store.appendAuditEvent(event("statement_imported_from_uri", NOW.plusSeconds(1), "second"));
    store.appendAuditEvent(event("anchor_added_or_replaced", NOW.plusSeconds(2), "third"));

    FileTrustGraphStore reopened = store(new TrustGraphStoreConfig(4, 4, 2, 65_536));
    List<TrustGraphAuditEvent> events = reopened.auditEvents(10);

    assertEquals(2, events.size());
    assertEquals("anchor_added_or_replaced", events.getFirst().eventType());
    assertEquals("statement_imported_from_uri", events.get(1).eventType());
    assertFalse(events.toString().contains("USK@private-insert"));
    assertFalse(events.getFirst().toJson().toString().contains(tempDir.toString()));
  }

  @Test
  void auditEvents_whenDuplicateEventsEvicted_expectOnlyOnePersistedDuplicateDeleted() {
    FileTrustGraphStore store = store(new TrustGraphStoreConfig(4, 4, 2, 65_536));
    TrustGraphAuditEvent duplicate = event("statement_import_rejected", NOW, "duplicate");
    store.appendAuditEvent(duplicate);
    store.appendAuditEvent(duplicate);
    store.appendAuditEvent(event("statement_imported", NOW.plusSeconds(1), "newer"));

    FileTrustGraphStore reopened = store(new TrustGraphStoreConfig(4, 4, 2, 65_536));
    List<String> statusCodes =
        reopened.auditEvents(10).stream().map(TrustGraphAuditEvent::statusCode).toList();

    assertEquals(List.of("newer", "duplicate"), statusCodes);
  }

  private FileTrustGraphStore store() {
    return store(TrustGraphStoreConfig.defaults());
  }

  private FileTrustGraphStore store(TrustGraphStoreConfig config) {
    return new FileTrustGraphStore(tempDir, config, Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static void openStore(java.nio.file.Path rootDirectory) {
    new FileTrustGraphStore(
        rootDirectory, TrustGraphStoreConfig.defaults(), Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static void openStore(
      java.nio.file.Path rootDirectory, java.nio.file.Path managedBoundaryDirectory) {
    new FileTrustGraphStore(
        rootDirectory,
        managedBoundaryDirectory,
        TrustGraphStoreConfig.defaults(),
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static List<String> retainedAnchors(FileTrustGraphStore store) {
    return store.anchors().stream().map(TrustAnchor::issuerFingerprint).toList();
  }

  private java.nio.file.Path firstAnchorRecord() throws java.io.IOException {
    try (var stream = java.nio.file.Files.list(tempDir.resolve("anchors"))) {
      return stream
          .filter(path -> path.getFileName().toString().endsWith(".properties"))
          .findFirst()
          .orElseThrow();
    }
  }

  private static void createSymbolicLinkOrSkip(java.nio.file.Path link, java.nio.file.Path target) {
    try {
      java.nio.file.Files.createSymbolicLink(link, target);
    } catch (UnsupportedOperationException | java.io.IOException | SecurityException exception) {
      Assumptions.assumeTrue(
          false, "Symbolic links are unavailable: " + exception.getClass().getSimpleName());
    }
  }

  private String allRelativePaths() throws java.io.IOException {
    try (var stream = java.nio.file.Files.walk(tempDir)) {
      return stream
          .map(path -> tempDir.relativize(path).toString())
          .sorted()
          .reduce("", (left, right) -> left + "\n" + right);
    }
  }

  private static TrustGraphAuditEvent event(String type, Instant timestamp, String status) {
    return new TrustGraphAuditEvent(
        type,
        timestamp,
        "trust-graph",
        "document-" + status,
        "payload-" + status,
        "issuer-" + status,
        "profile",
        TrustStatementFingerprint.sha256Hex(
            "USK@private-insert".getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        "USK@sha256:0123456789abcdef",
        "content-fetch",
        TrustStatementFingerprint.sha256Hex(
            "USK@private-insert".getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        "USK@sha256:0123456789abcdef",
        Boolean.TRUE,
        status);
  }

  private static TrustGraphQuery query() {
    return new TrustGraphQuery(
        TrustSubjectKind.PROFILE, "USK@example/subject/profile.json", "profile");
  }

  private static String fingerprint(TrustStatementDocument document) {
    return document.payload().issuer().publicKeyFingerprint();
  }

  private static TrustStatementDocument signedStatement(int score, int confidence)
      throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
    KeyPair keyPair = generator.generateKeyPair();
    String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    TrustIssuer issuer =
        new TrustIssuer(
            "issuer-" + score + "-" + confidence + "-" + System.nanoTime(),
            TrustStatementFingerprint.sha256Hex(keyPair.getPublic().getEncoded()),
            publicKeyBase64,
            "USK@example/profile.json");
    TrustStatementPayload payload =
        new TrustStatementPayload(
            issuer,
            new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/subject/profile.json", null),
            "profile",
            score,
            confidence,
            "known publisher",
            List.of("fixture"),
            NOW.minusSeconds(60),
            null);
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
    String signatureBase64 = Base64.getEncoder().encodeToString(signer.sign());
    return new TrustStatementDocument(
        TrustDocumentTypes.TRUST_STATEMENT_V1,
        payload,
        new TrustSignatureEnvelope(
            TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            signatureBase64));
  }
}
