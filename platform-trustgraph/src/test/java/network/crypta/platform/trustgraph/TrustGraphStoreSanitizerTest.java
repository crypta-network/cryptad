package network.crypta.platform.trustgraph;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustGraphStoreSanitizerTest {
  @Test
  void normalizeSourceUri_whenCryptaWrappedContentKey_expectCanonicalSchemeAndRedactedSummary() {
    String sourceUri = "Crypta:CHK@example/trust/1/trust.json";

    String normalized = TrustGraphStoreSanitizer.normalizeSourceUri(sourceUri);
    String summary =
        java.util.Objects.requireNonNull(TrustGraphStoreSanitizer.redactedUriSummary(sourceUri));
    String hash =
        java.util.Objects.requireNonNull(TrustGraphStoreSanitizer.sourceUriHash(sourceUri));

    assertEquals("crypta:CHK@example/trust/1/trust.json", normalized);
    assertTrue(summary.startsWith("CHK@sha256:"), summary);
    assertFalse(summary.contains("example"), summary);
    assertFalse(summary.contains("trust.json"), summary);
    assertEquals(64, hash.length());
    assertTrue(hash.matches("[0-9a-f]{64}"), hash);
  }

  @Test
  void normalizeSourceUri_whenNull_expectNullMetadata() {
    assertNull(TrustGraphStoreSanitizer.normalizeSourceUri(null));
    assertNull(TrustGraphStoreSanitizer.redactedUriSummary(null));
    assertNull(TrustGraphStoreSanitizer.sourceUriHash(null));
  }

  @Test
  void normalizeSourceUri_whenUnsupportedOrUnsafe_expectInvalidTrustStatement() {
    for (String sourceUri :
        java.util.List.of(
            "/tmp/trust.json",
            "\\\\server\\share\\trust.json",
            "file:///tmp/trust.json",
            "http://example.invalid/trust.json",
            "crypta:http://example.invalid/trust.json",
            "crypta: CHK@example/trust.json",
            "CHK@example/trust statement.json",
            "CHK@example/trust.json?token=secret",
            "CHK@example/trust.json#fragment")) {
      TrustGraphException exception =
          assertThrows(
              TrustGraphException.class,
              () -> TrustGraphStoreSanitizer.normalizeSourceUri(sourceUri),
              sourceUri);

      assertEquals("invalid_trust_statement", exception.errorCode(), sourceUri);
    }
  }

  @Test
  void normalizePersistedSourceUriSummary_whenUnsafe_expectInvalidTrustStatement() {
    for (String sourceSummary :
        java.util.List.of(
            "CHK@example/trust.json",
            "CHK@sha256:0123456789abcdef/path",
            "CHK@sha256:0123456789abcdef\\path",
            "CHK@sha256:0123456789abcdef value",
            "CHK@sha256:01234567\n89abcdef")) {
      TrustGraphException exception =
          assertThrows(
              TrustGraphException.class,
              () -> TrustGraphStoreSanitizer.normalizeSourceUriSummary(sourceSummary),
              sourceSummary);

      assertEquals("invalid_trust_statement", exception.errorCode(), sourceSummary);
    }
  }

  @Test
  void normalizeSourceUriHash_whenMalformed_expectInvalidTrustStatement() {
    for (String sourceUriHash :
        java.util.List.of(
            "A".repeat(64), "0".repeat(63), "g" + "0".repeat(63), "0".repeat(64) + "0")) {
      TrustGraphException exception =
          assertThrows(
              TrustGraphException.class,
              () -> TrustGraphStoreSanitizer.normalizeSourceUriHash(sourceUriHash),
              sourceUriHash);

      assertEquals("invalid_trust_statement", exception.errorCode(), sourceUriHash);
    }
  }

  @Test
  void auditText_whenBlankOptionalAndTrimmedRequired_expectNullOrTrimmedValue() {
    assertNull(TrustGraphStoreSanitizer.optionalAuditText("source", "  ", 16));
    assertEquals("ok", TrustGraphStoreSanitizer.requiredAuditText("status", " ok ", 16));
  }

  @Test
  void auditText_whenRequiredMissingOrUnsafe_expectInvalidAuditEvent() {
    for (String value : java.util.List.of("", "  ", "ok\nbad", "x".repeat(17))) {
      TrustGraphException exception =
          assertThrows(
              TrustGraphException.class,
              () -> TrustGraphStoreSanitizer.requiredAuditText("status", value, 16),
              value);

      assertEquals("invalid_trust_audit_event", exception.errorCode(), value);
    }
  }
}
