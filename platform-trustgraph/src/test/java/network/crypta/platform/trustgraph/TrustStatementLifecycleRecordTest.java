package network.crypta.platform.trustgraph;

import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TrustStatementLifecycleRecordTest {
  private static final Instant CREATED_AT = Instant.parse("2026-05-17T00:00:00Z");
  private static final Instant UPDATED_AT = Instant.parse("2026-05-17T00:01:00Z");

  @Test
  void parse_whenJsonTokenOrEnumNameProvided_expectLifecycleStatus() {
    assertEquals(
        TrustStatementLifecycleStatus.ACTIVE, TrustStatementLifecycleStatus.parse("active"));
    assertEquals(
        TrustStatementLifecycleStatus.DEPRECATED,
        TrustStatementLifecycleStatus.parse("DEPRECATED"));
    assertEquals(
        TrustStatementLifecycleStatus.REVOKED, TrustStatementLifecycleStatus.parse("Revoked"));
  }

  @Test
  void parse_whenUnsupportedStatusProvided_expectLifecycleValidationError() {
    TrustGraphException exception =
        assertThrows(
            TrustGraphException.class, () -> TrustStatementLifecycleStatus.parse("global-blocked"));

    assertEquals("invalid_trust_statement_lifecycle", exception.errorCode());
  }

  @Test
  void updated_whenFieldsNeedNormalization_expectBoundedLocalLifecycleRecord() {
    TrustStatementLifecycleRecord lifecycleRecord =
        TrustStatementLifecycleRecord.updated(
            "statement-fingerprint",
            TrustStatementLifecycleStatus.REVOKED,
            "Operator-Revoked",
            " local note ",
            "crypta:CHK@replacement-statement",
            CREATED_AT,
            UPDATED_AT,
            " trust-graph ",
            "unknown-source");

    assertEquals(TrustStatementLifecycleStatus.REVOKED, lifecycleRecord.status());
    assertEquals("operator-revoked", lifecycleRecord.reasonCode());
    assertEquals("local note", lifecycleRecord.note());
    assertEquals("trust-graph", lifecycleRecord.actorAppId());
    assertEquals("operator", lifecycleRecord.source());
    assertTrue(lifecycleRecord.replacementUri().startsWith("CHK@sha256:"));
    assertTrue(lifecycleRecord.toJson().containsKey("replacementUri"));
    assertTrue(lifecycleRecord.toJson().toString().contains("operator-revoked"));
    assertFalse(lifecycleRecord.toJson().toString().contains("replacement-statement"));
  }

  @Test
  void updated_whenReasonCodeIsInvalid_expectLifecycleValidationError() {
    TrustGraphException exception =
        assertThrows(
            TrustGraphException.class,
            () ->
                TrustStatementLifecycleRecord.updated(
                    "statement-fingerprint",
                    TrustStatementLifecycleStatus.DEPRECATED,
                    "not a token",
                    null,
                    null,
                    CREATED_AT,
                    UPDATED_AT,
                    null,
                    "operator"));

    assertEquals("invalid_trust_statement_lifecycle", exception.errorCode());
  }

  @Test
  void active_whenNoStoredLifecycleExists_expectDefaultActiveLocalRecord() {
    TrustStatementLifecycleRecord lifecycleRecord =
        TrustStatementLifecycleRecord.active("statement-fingerprint", CREATED_AT);

    assertEquals(TrustStatementLifecycleStatus.ACTIVE, lifecycleRecord.status());
    assertEquals("default-active", lifecycleRecord.reasonCode());
    assertNull(lifecycleRecord.note());
    assertNull(lifecycleRecord.replacementUri());
    assertEquals("default", lifecycleRecord.source());
    assertEquals(CREATED_AT, lifecycleRecord.createdAt());
    assertEquals(CREATED_AT, lifecycleRecord.updatedAt());
  }
}
