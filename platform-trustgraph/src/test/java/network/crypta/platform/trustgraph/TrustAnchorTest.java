package network.crypta.platform.trustgraph;

import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TrustAnchorTest {
  private static final Instant NOW = Instant.parse("2026-05-17T00:00:00Z");

  @Test
  void constructor_whenReasonCodeNeedsNormalization_expectStableToken() {
    TrustAnchor anchor =
        new TrustAnchor(
            "fingerprint-1",
            "Alice",
            "manual",
            NOW,
            TrustStatementLifecycleStatus.REVOKED,
            NOW,
            "Operator-Revoked");

    assertEquals("operator-revoked", anchor.reasonCode());
    assertEquals("operator-revoked", anchor.toJson().get("reasonCode"));
  }

  @Test
  void constructor_whenReasonCodeOmitted_expectStatusDefaultToken() {
    TrustAnchor active = new TrustAnchor("fingerprint-1", "Alice", "manual", NOW);
    TrustAnchor deprecated =
        new TrustAnchor(
            "fingerprint-2",
            "Bob",
            "manual",
            NOW,
            TrustStatementLifecycleStatus.DEPRECATED,
            NOW,
            null);

    assertEquals("local-anchor", active.reasonCode());
    assertEquals("operator-deprecated", deprecated.reasonCode());
  }

  @Test
  void constructor_whenReasonCodeContainsPathOrTokenLikeText_expectLifecycleValidationError() {
    TrustGraphException pathException =
        assertThrows(
            TrustGraphException.class,
            () ->
                new TrustAnchor(
                    "fingerprint-1",
                    "Alice",
                    "manual",
                    NOW,
                    TrustStatementLifecycleStatus.REVOKED,
                    NOW,
                    "/home/alice/secret"));
    TrustGraphException tokenException =
        assertThrows(
            TrustGraphException.class,
            () ->
                new TrustAnchor(
                    "fingerprint-2",
                    "Bob",
                    "manual",
                    NOW,
                    TrustStatementLifecycleStatus.REVOKED,
                    NOW,
                    "token:abc"));

    assertEquals("invalid_trust_statement_lifecycle", pathException.errorCode());
    assertEquals("invalid_trust_statement_lifecycle", tokenException.errorCode());
    assertFalse(pathException.getMessage().contains("/home/alice/secret"));
    assertFalse(tokenException.getMessage().contains("token:abc"));
  }

  @Test
  void toJson_whenReasonCodeAccepted_expectNoPathOrTokenMaterial() {
    TrustAnchor anchor =
        new TrustAnchor(
            "fingerprint-1",
            "Alice",
            "manual",
            NOW,
            TrustStatementLifecycleStatus.ACTIVE,
            NOW,
            "local.anchor_1");

    String json = anchor.toJson().toString();

    assertTrue(json.contains("local.anchor_1"));
    assertFalse(json.contains("/home/"));
    assertFalse(json.contains("token:"));
  }
}
