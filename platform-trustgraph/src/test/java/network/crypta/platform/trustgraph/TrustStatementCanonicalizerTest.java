package network.crypta.platform.trustgraph;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TrustStatementCanonicalizerTest {
  @Test
  void canonicalPayloadBytes_whenPayloadHasOptionals_expectExactDomainSeparatedBytes() {
    TrustStatementPayload payload =
        new TrustStatementPayload(
            new TrustIssuer("issuer-1", "fingerprint-1", "public-key", "USK@example/profile.json"),
            new TrustSubject(
                TrustSubjectKind.PROFILE,
                "USK@example/subject/profile.json",
                "subject-fingerprint"),
            "profile",
            50,
            80,
            "known publisher",
            List.of("first", "second"),
            Instant.parse("2026-05-16T00:00:00Z"),
            Instant.parse("2026-11-16T00:00:00Z"));

    String canonical =
        new String(
            TrustStatementCanonicalizer.canonicalPayloadBytes(payload), StandardCharsets.UTF_8);

    assertEquals(
        "crypta.trust.statement.v1\n"
            + "{\"issuer\":{\"identityId\":\"issuer-1\","
            + "\"publicKeyFingerprint\":\"fingerprint-1\","
            + "\"publicKeyBase64\":\"public-key\","
            + "\"profileUri\":\"USK@example/profile.json\"},"
            + "\"subject\":{\"kind\":\"profile\","
            + "\"uri\":\"USK@example/subject/profile.json\","
            + "\"fingerprint\":\"subject-fingerprint\"},"
            + "\"context\":\"profile\","
            + "\"score\":50,"
            + "\"confidence\":80,"
            + "\"reason\":\"known publisher\","
            + "\"tags\":[\"first\",\"second\"],"
            + "\"issuedAt\":\"2026-05-16T00:00:00Z\","
            + "\"expiresAt\":\"2026-11-16T00:00:00Z\"}",
        canonical);
  }

  @Test
  void canonicalPayloadBytes_whenOptionalsOmitted_expectStableMinimalBytes() {
    TrustStatementPayload payload =
        new TrustStatementPayload(
            new TrustIssuer("issuer-1", "fingerprint-1", null, null),
            new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/subject/profile.json", null),
            "profile",
            50,
            80,
            null,
            List.of(),
            Instant.parse("2026-05-16T00:00:00Z"),
            null);

    String canonical =
        new String(
            TrustStatementCanonicalizer.canonicalPayloadBytes(payload), StandardCharsets.UTF_8);

    assertEquals(
        "crypta.trust.statement.v1\n"
            + "{\"issuer\":{\"identityId\":\"issuer-1\","
            + "\"publicKeyFingerprint\":\"fingerprint-1\"},"
            + "\"subject\":{\"kind\":\"profile\","
            + "\"uri\":\"USK@example/subject/profile.json\"},"
            + "\"context\":\"profile\","
            + "\"score\":50,"
            + "\"confidence\":80,"
            + "\"issuedAt\":\"2026-05-16T00:00:00Z\"}",
        canonical);
    assertTrue(canonical.indexOf("\"score\"") < canonical.indexOf("\"confidence\""));
  }
}
