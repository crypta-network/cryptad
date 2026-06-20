package network.crypta.platform.trustgraph;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustGraphImportPreviewTest {
  private static final Instant NOW = Instant.parse("2026-05-17T00:00:00Z");
  private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  private static final String SUBJECT_URI = "USK@example/subject/profile.json";
  private static final int STATEMENT_CONFIDENCE = 50;

  @Test
  void preview_whenCandidateIsNull_expectRejectedPreviewInsteadOfException() {
    for (String documentJson : List.of("[null]", "{\"statements\":[null]}", "null")) {
      InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(FIXED_CLOCK);

      Map<String, Object> preview =
          TrustGraphImportPreview.preview(
                  documentJson, store, "CHK@statement", "fixture", 65_536, NOW)
              .toJson();

      assertEquals(1, preview.get("candidateStatementCount"));
      assertEquals(0, preview.get("acceptedCount"));
      assertEquals(1, preview.get("rejectedCount"));
      assertTrue(preview.toString().contains("invalid_trust_statement"));
    }
  }

  @Test
  void preview_whenDuplicateIssuerConflictsWithStoredStatement_expectMaterialRiskAndRedaction()
      throws Exception {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(FIXED_CLOCK);
    KeyPair issuerKeys = keyPair();
    TrustStatementDocument existing = signedStatement(issuerKeys, 40);
    TrustStatementDocument conflicting = signedStatement(issuerKeys, -20);
    store.importStatement(
        existing, "manual", "crypta:USK@private-insert/trust/0/trust.json", "existing");

    Map<String, Object> preview =
        TrustGraphImportPreview.preview(
                TrustJson.write(Map.of("statements", List.of(conflicting.toJson()))),
                store,
                "crypta:USK@private-insert/trust/1/trust.json",
                "conflict",
                65_536,
                NOW)
            .toJson();
    List<?> summaries = (List<?>) preview.get("candidateSummaries");
    Map<?, ?> summary = (Map<?, ?>) summaries.getFirst();

    assertEquals(1, preview.get("candidateStatementCount"));
    assertEquals(1, preview.get("acceptedCount"));
    assertEquals(0, preview.get("rejectedCount"));
    assertEquals(1, preview.get("duplicateIssuerCount"));
    assertEquals(1, preview.get("conflictCount"));
    assertEquals(Boolean.TRUE, preview.get("materialRisk"));
    assertEquals("conflict", summary.get("conflictStatus"));
    assertEquals(Boolean.TRUE, summary.get("duplicateIssuer"));
    assertEquals(64, String.valueOf(summary.get("subjectUriHash")).length());
    assertFalse(preview.toString().contains(SUBJECT_URI));
    assertFalse(preview.toString().contains("private-insert"));
  }

  @Test
  void preview_whenInputExceedsMaxBytes_expectRejectedWithoutCandidateSummaries() throws Exception {
    TrustStatementDocument document = signedStatement(keyPair(), 80);

    Map<String, Object> preview =
        TrustGraphImportPreview.preview(
                TrustJson.write(document.toJson()),
                new InMemoryTrustGraphStore(FIXED_CLOCK),
                "crypta:USK@private-insert/trust/0/trust.json",
                "oversized",
                4,
                NOW)
            .toJson();

    assertEquals(0, preview.get("candidateStatementCount"));
    assertEquals(0, preview.get("acceptedCount"));
    assertEquals(1, preview.get("rejectedCount"));
    assertTrue(((List<?>) preview.get("candidateSummaries")).isEmpty());
    assertTrue(((List<?>) preview.get("warnings")).contains("input-too-large"));
    assertEquals(Boolean.TRUE, preview.get("rawContentDiscarded"));
    assertFalse(preview.toString().contains("private-insert"));
  }

  @Test
  void preview_whenCandidateCountExceedsLimit_expectRejectedOverflowAndBoundedSummaries()
      throws Exception {
    TrustStatementDocument document = signedStatement(keyPair(), 80);
    ArrayList<Object> candidates = new ArrayList<>();
    for (int index = 0; index < TrustGraphImportPreview.MAX_PREVIEW_STATEMENTS + 2; index++) {
      candidates.add(document.toJson());
    }

    Map<String, Object> preview =
        TrustGraphImportPreview.preview(
                TrustJson.write(Map.of("statements", candidates)),
                new InMemoryTrustGraphStore(FIXED_CLOCK),
                "CHK@statement",
                "many candidates",
                65_536,
                NOW)
            .toJson();

    assertEquals(
        TrustGraphImportPreview.MAX_PREVIEW_STATEMENTS + 2, preview.get("candidateStatementCount"));
    assertEquals(1, preview.get("acceptedCount"));
    assertEquals(2, preview.get("rejectedCount"));
    assertEquals(TrustGraphImportPreview.MAX_PREVIEW_STATEMENTS - 1, preview.get("duplicateCount"));
    assertEquals(
        TrustGraphImportPreview.MAX_CANDIDATE_SUMMARIES,
        ((List<?>) preview.get("candidateSummaries")).size());
    assertTrue(((List<?>) preview.get("warnings")).contains("candidate-count-exceeds-preview-cap"));
  }

  private static KeyPair keyPair() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private static TrustStatementDocument signedStatement(KeyPair keyPair, int score)
      throws Exception {
    String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    TrustIssuer issuer =
        new TrustIssuer(
            "issuer-" + score + "-" + STATEMENT_CONFIDENCE,
            TrustStatementFingerprint.sha256Hex(keyPair.getPublic().getEncoded()),
            publicKeyBase64,
            "USK@example/profile.json");
    TrustStatementPayload payload =
        new TrustStatementPayload(
            issuer,
            new TrustSubject(TrustSubjectKind.PROFILE, SUBJECT_URI, null),
            "profile",
            score,
            STATEMENT_CONFIDENCE,
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
  }
}
