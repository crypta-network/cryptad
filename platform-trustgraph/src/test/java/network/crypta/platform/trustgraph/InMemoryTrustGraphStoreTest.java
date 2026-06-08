package network.crypta.platform.trustgraph;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class InMemoryTrustGraphStoreTest {
  private static final Instant NOW = Instant.parse("2026-05-17T00:00:00Z");

  @Test
  void lifecycle_whenStatementReimportedAfterRevocation_expectRecordPreservedAndMetadataUpdated() {
    InMemoryTrustGraphStore store = store();
    TrustStatementDocument document = signedStatement();

    TrustGraphImportResult first =
        store.importStatement(
            document,
            "local-import",
            "crypta:USK@private-insert-statement",
            "Initial import",
            "trust.sub:1");
    TrustStatementLifecycleRecord revoked =
        store.updateLifecycle(
            first.documentFingerprint(),
            TrustStatementLifecycleStatus.REVOKED,
            "Operator-Revoked",
            "local policy replacement",
            "crypta:CHK@replacement-statement",
            "trust-graph",
            "app");
    TrustGraphImportResult second =
        store.importStatement(
            document,
            "subscription",
            "crypta:SSK@subscription-statement",
            "Subscription import",
            "trust.sub:2");

    TrustGraphStore.StoredTrustStatement stored = store.statement(first.documentFingerprint());
    TrustStatementLifecycleRecord retained = store.lifecycle(first.documentFingerprint());

    assertTrue(first.imported());
    assertFalse(second.imported());
    assertEquals(1, store.statementCount());
    assertNotNull(stored);
    assertEquals(TrustStatementLifecycleStatus.REVOKED, revoked.status());
    assertEquals(TrustStatementLifecycleStatus.REVOKED, retained.status());
    assertEquals("operator-revoked", retained.reasonCode());
    assertEquals("app", retained.source());
    assertEquals("subscription", stored.source());
    assertEquals("crypta-ssk", stored.sourceUriKind());
    assertEquals("trust.sub:2", stored.subscriptionId());
    assertEquals("Subscription import", stored.sourceLabel());
    assertTrue(stored.sourceUri().startsWith("SSK@sha256:"));
    assertEquals(64, stored.sourceUriHash().length());
    assertTrue(retained.replacementUri().startsWith("CHK@sha256:"));
    assertFalse(stored.toSummaryJson(retained).toString().contains("subscription-statement"));
    assertFalse(retained.toJson().toString().contains("replacement-statement"));
    assertFalse(retained.toJson().toString().contains("private-insert"));
  }

  @Test
  void lifecycle_whenNoLocalRecordExists_expectSyntheticActiveRecordAtImportTime() {
    InMemoryTrustGraphStore store = store();
    TrustGraphImportResult imported =
        store.importStatement(signedStatement(), "local-import", null, null);

    TrustStatementLifecycleRecord lifecycle = store.lifecycle(imported.documentFingerprint());

    assertEquals(TrustStatementLifecycleStatus.ACTIVE, lifecycle.status());
    assertEquals("default-active", lifecycle.reasonCode());
    assertEquals(imported.importedAt(), lifecycle.createdAt());
    assertEquals(imported.importedAt(), lifecycle.updatedAt());
  }

  @Test
  void updateLifecycle_whenStatementIsUnknown_expectTrustStatementNotFound() {
    InMemoryTrustGraphStore store = store();

    TrustGraphException exception =
        assertThrows(
            TrustGraphException.class,
            () ->
                store.updateLifecycle(
                    "missing-fingerprint",
                    TrustStatementLifecycleStatus.DEPRECATED,
                    null,
                    null,
                    null,
                    "trust-graph",
                    "app"));

    assertEquals("trust_statement_not_found", exception.errorCode());
  }

  private static InMemoryTrustGraphStore store() {
    return new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static TrustStatementDocument signedStatement() {
    try {
      KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
      String fingerprint = TrustStatementFingerprint.sha256Hex(keyPair.getPublic().getEncoded());
      TrustStatementPayload payload =
          new TrustStatementPayload(
              new TrustIssuer(
                  "issuer-" + fingerprint.substring(0, 12),
                  fingerprint,
                  publicKeyBase64,
                  "USK@example/profile.json"),
              new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/profile.json", null),
              "profile",
              80,
              50,
              "known publisher",
              List.of("fixture"),
              NOW.minusSeconds(60),
              null);
      Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(keyPair.getPrivate());
      signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
      return new TrustStatementDocument(
          TrustDocumentTypes.TRUST_STATEMENT_V1,
          payload,
          new TrustSignatureEnvelope(
              TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
              TrustDocumentTypes.TRUST_STATEMENT_V1,
              Base64.getEncoder().encodeToString(signer.sign())));
    } catch (GeneralSecurityException exception) {
      throw new AssertionError("Failed to create signed trust statement fixture.", exception);
    }
  }
}
