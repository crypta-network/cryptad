package network.crypta.platform.trustgraph;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TrustStatementParserTest {
  @Test
  void parse_whenStatementIsValid_expectBoundedModelAndCanonicalPayload() {
    TrustStatementDocument document = TrustStatementParser.parse(validStatement());

    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_V1, document.type());
    assertEquals("issuer-1", document.payload().issuer().identityId());
    assertEquals("profile", document.payload().subject().kind().jsonValue());
    assertEquals(50, document.payload().score());
    assertEquals(80, document.payload().confidence());
    assertEquals(List.of("example"), document.payload().tags());
    assertEquals(
        "{\"issuer\":{\"identityId\":\"issuer-1\",\"publicKeyFingerprint\":\"fingerprint-1\","
            + "\"profileUri\":\"USK@example/profile.json\"},\"subject\":{\"kind\":\"profile\","
            + "\"uri\":\"USK@example/subject/profile.json\"},\"context\":\"profile\","
            + "\"score\":50,\"confidence\":80,\"reason\":\"known publisher\","
            + "\"tags\":[\"example\"],\"issuedAt\":\"2026-05-16T00:00:00Z\","
            + "\"expiresAt\":\"2026-11-16T00:00:00Z\"}",
        TrustStatementCanonicalizer.canonicalPayloadJson(document.payload()));
    assertTrue(
        new String(
                TrustStatementCanonicalizer.canonicalPayloadBytes(document.payload()),
                StandardCharsets.UTF_8)
            .startsWith("crypta.trust.statement.v1\n{"));
  }

  @Test
  void parse_whenUnknownFieldPresent_expectRejectionBeforeSigning() {
    String document = validStatement().replace("\"payload\": {", "\"payload\": {\"extra\": true,");

    TrustGraphException exception =
        assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(document));

    assertEquals("invalid_trust_statement", exception.errorCode());
    assertTrue(exception.getMessage().contains("Unknown field"));
  }

  @Test
  void parse_whenOversizedMalformedJson_expectRejectedBeforeParsing() {
    String document = "{" + " ".repeat(TrustStatementValidator.MAX_DOCUMENT_BYTES + 1);

    TrustGraphException exception =
        assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(document));

    assertEquals("trust_statement_too_large", exception.errorCode());
  }

  @Test
  void parse_whenDuplicateObjectMemberPresent_expectRejectionBeforeCanonicalization() {
    String duplicateRoot = validStatement().replace("\"type\":", "\"type\":\"wrong\",\"type\":");
    String duplicatePayload =
        validStatement().replace("\"score\": 50", "\"score\": -50, \"score\": 50");
    String duplicateSignature =
        validStatement()
            .replace(
                "\"value\": \"signature-value\"",
                "\"value\": \"ignored-signature\", \"value\": \"signature-value\"");

    for (String document : List.of(duplicateRoot, duplicatePayload, duplicateSignature)) {
      TrustGraphException exception =
          assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(document));
      assertEquals("invalid_trust_json", exception.errorCode());
      assertTrue(exception.getMessage().contains("Duplicate JSON object members"));
    }
  }

  @Test
  void parse_whenScoreOrConfidenceInvalid_expectRejection() {
    String invalidScoreDocument = validStatement().replace("\"score\": 50", "\"score\": 101");
    String invalidConfidenceDocument =
        validStatement().replace("\"confidence\": 80", "\"confidence\": -1");
    String stringScoreDocument = validStatement().replace("\"score\": 50", "\"score\": \"50\"");
    String decimalScoreDocument = validStatement().replace("\"score\": 50", "\"score\": 50.5");

    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(invalidScoreDocument));
    assertThrows(
        TrustGraphException.class, () -> TrustStatementParser.parse(invalidConfidenceDocument));
    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(stringScoreDocument));
    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(decimalScoreDocument));
  }

  @Test
  void parse_whenPublicTextContainsIsoControl_expectRejection() {
    String nulSubject =
        validStatement().replace("USK@example/subject/profile.json", "USK@example/subject\\u0000");
    String c1Issuer = validStatement().replace("fingerprint-1", "fingerprint-1\\u0085");

    for (String document : List.of(nulSubject, c1Issuer)) {
      TrustGraphException exception =
          assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(document));

      assertEquals("invalid_trust_statement", exception.errorCode());
      assertTrue(exception.getMessage().contains("control characters"));
    }
  }

  @Test
  void parse_whenTagsAreMalformedOrOversized_expectRejection() {
    String blankTag = validStatement().replace("\"tags\": [\"example\"]", "\"tags\": [\"\"]");
    String longTag =
        validStatement()
            .replace("\"tags\": [\"example\"]", "\"tags\": [\"" + "a".repeat(64) + "\"]");
    String manyTags =
        validStatement()
            .replace(
                "\"tags\": [\"example\"]",
                "\"tags\": [\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\",\"10\","
                    + "\"11\",\"12\",\"13\",\"14\",\"15\",\"16\",\"17\"]");

    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(blankTag));
    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(longTag));
    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(manyTags));
  }

  @Test
  void parse_whenContextOrSubjectInvalid_expectRejection() {
    String invalidContextDocument =
        validStatement().replace("\"context\": \"profile\"", "\"context\": \"spam\"");
    String invalidSubjectDocument =
        validStatement().replace("\"kind\": \"profile\"", "\"kind\": \"peer\"");

    assertThrows(
        TrustGraphException.class, () -> TrustStatementParser.parse(invalidContextDocument));
    assertThrows(
        TrustGraphException.class, () -> TrustStatementParser.parse(invalidSubjectDocument));
  }

  @Test
  void parse_whenExpiresAtBeforeIssuedAt_expectRejection() {
    String document =
        validStatement()
            .replace(
                "\"expiresAt\": \"2026-11-16T00:00:00Z\"",
                "\"expiresAt\": \"2026-01-16T00:00:00Z\"");

    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(document));
  }

  @Test
  void parse_whenSignatureAlgorithmInvalid_expectRejection() {
    String document =
        validStatement()
            .replace(
                "\"algorithm\": \"app-vault-ed25519-preview\"",
                "\"algorithm\": \"generic-ed25519\"");

    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(document));
  }

  @Test
  void toString_whenCalled_expectSignatureAndReasonAreRedacted() {
    TrustStatementDocument document = TrustStatementParser.parse(validStatement());
    String text = document.toString();

    assertTrue(text.contains("signature=<redacted>"));
    assertFalse(text.contains("signature-value"));
    assertFalse(text.contains("known publisher"));
  }

  static String validStatement() {
    return """
    {
      "type": "crypta.trust.statement.v1",
      "payload": {
        "issuer": {
          "identityId": "issuer-1",
          "publicKeyFingerprint": "fingerprint-1",
          "profileUri": "USK@example/profile.json"
        },
        "subject": {
          "kind": "profile",
          "uri": "USK@example/subject/profile.json"
        },
        "context": "profile",
        "score": 50,
        "confidence": 80,
        "reason": "known publisher",
        "tags": ["example"],
        "issuedAt": "2026-05-16T00:00:00Z",
        "expiresAt": "2026-11-16T00:00:00Z"
      },
      "signature": {
        "algorithm": "app-vault-ed25519-preview",
        "domain": "crypta.trust.statement.v1",
        "value": "signature-value"
      }
    }
    """;
  }

  @SuppressWarnings("unused")
  static TrustStatementDocument statement(
      String fingerprint, int score, int confidence, String issuedAt, String expiresAt) {
    return new TrustStatementDocument(
        TrustDocumentTypes.TRUST_STATEMENT_V1,
        new TrustStatementPayload(
            new TrustIssuer("issuer-" + fingerprint, fingerprint, null),
            new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/profile.json", null),
            "profile",
            score,
            confidence,
            null,
            List.of(),
            Instant.parse(issuedAt),
            expiresAt == null ? null : Instant.parse(expiresAt)),
        new TrustSignatureEnvelope(
            TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            "signature-" + fingerprint));
  }
}
