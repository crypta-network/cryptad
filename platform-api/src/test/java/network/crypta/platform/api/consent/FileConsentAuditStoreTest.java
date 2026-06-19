package network.crypta.platform.api.consent;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class FileConsentAuditStoreTest {
  @TempDir private Path tempDir;

  @Test
  void append_whenBackedByFile_expectJsonLineAndIndexedEvent() throws Exception {
    Path auditLog = tempDir.resolve("consent/audit.jsonl");
    FileConsentAuditStore store = new FileConsentAuditStore(auditLog);
    ConsentAuditEvent first = auditEvent("decision-1", "example.app");
    ConsentAuditEvent second = auditEvent("decision-2", "other.app");

    store.append(first);
    store.append(second);

    List<String> lines = Files.readAllLines(auditLog, StandardCharsets.UTF_8);
    List<ConsentAuditEvent> appEvents = store.list("example.app");
    List<ConsentAuditEvent> allEvents = store.list(null);
    assertEquals(2, lines.size());
    assertTrue(lines.get(0).contains("\"decisionId\":\"decision-1\""));
    assertTrue(lines.get(1).contains("\"decisionId\":\"decision-2\""));
    assertEquals(List.of(first), appEvents);
    assertEquals(List.of(first, second), allEvents);
  }

  private static ConsentAuditEvent auditEvent(String decisionId, String appId) {
    return new ConsentAuditEvent(
        decisionId,
        "request-" + decisionId,
        "local_operator",
        appId,
        ConsentActionType.UPDATE_APP,
        ConsentDecisionStatus.APPROVED,
        Instant.parse("2026-05-01T00:00:00Z"),
        "sha256:0123456789abcdef",
        List.of("permission_required"));
  }
}
