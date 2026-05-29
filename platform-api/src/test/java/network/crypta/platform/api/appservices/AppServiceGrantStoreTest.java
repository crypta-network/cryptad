package network.crypta.platform.api.appservices;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppServiceGrantStoreTest {
  @TempDir private Path tempDir;

  @Test
  void fileStore_whenGrantsReload_expectDeterministicOrderingAndRedactedJson() throws Exception {
    FileAppServiceGrantStore store = new FileAppServiceGrantStore(tempDir.resolve("app-services"));
    AppServiceGrant later =
        grant("asg-222222222222222222222222", Instant.parse("2026-05-24T12:00:02Z"));
    AppServiceGrant earlier =
        grant("asg-111111111111111111111111", Instant.parse("2026-05-24T12:00:01Z"));

    store.writeGrant(later);
    store.writeGrant(earlier);
    FileAppServiceGrantStore reloaded =
        new FileAppServiceGrantStore(tempDir.resolve("app-services"));

    List<AppServiceGrant> grants = reloaded.listGrants();
    assertEquals(
        List.of(earlier.grantId(), later.grantId()),
        grants.stream().map(AppServiceGrant::grantId).toList());
    assertEquals(earlier, reloaded.readGrant(earlier.grantId()).orElseThrow());
    String publicJson = earlier.toJson().toString();
    assertFalse(publicJson.contains(tempDir.toString()));
    assertFalse(publicJson.contains("raw-token"));
  }

  @Test
  void fileStore_whenAuditEventsReload_expectNewestFirstAndRedactedSubjectHash() throws Exception {
    FileAppServiceGrantStore store = new FileAppServiceGrantStore(tempDir.resolve("app-services"));
    AppServiceAuditEvent older =
        event("ase-111111111111111111111111", Instant.parse("2026-05-24T12:00:01Z"));
    AppServiceAuditEvent newer =
        event("ase-222222222222222222222222", Instant.parse("2026-05-24T12:00:02Z"));

    store.appendAuditEvent(older);
    store.appendAuditEvent(newer);
    List<AppServiceAuditEvent> events =
        new FileAppServiceGrantStore(tempDir.resolve("app-services")).listAuditEvents(10);

    assertEquals(
        List.of(newer.eventId(), older.eventId()),
        events.stream().map(AppServiceAuditEvent::eventId).toList());
    assertEquals("sha256:abc", events.getFirst().subjectUriHash());
    assertTrue(events.getFirst().toJson().toString().contains("sha256:abc"));
    assertFalse(events.getFirst().toJson().toString().contains("SSK@private"));
  }

  @Test
  void fileStore_whenAuditRetentionExceeded_expectOldestFilesPruned() throws Exception {
    Path root = tempDir.resolve("app-services");
    FileAppServiceGrantStore store = new FileAppServiceGrantStore(root);
    Instant base = Instant.parse("2026-05-24T12:00:00Z");

    for (int index = 0; index < 515; index++) {
      store.appendAuditEvent(event(index, base.plusSeconds(index)));
    }

    Path auditDirectory = root.resolve("audit");
    try (var files = Files.list(auditDirectory)) {
      assertEquals(
          512, files.filter(path -> path.getFileName().toString().endsWith(".properties")).count());
    }
    assertFalse(Files.exists(auditDirectory.resolve(eventId(0) + ".properties")));
    assertFalse(Files.exists(auditDirectory.resolve(eventId(2) + ".properties")));
    assertTrue(Files.exists(auditDirectory.resolve(eventId(3) + ".properties")));
    assertEquals(eventId(514), store.listAuditEvents(10).getFirst().eventId());
  }

  @Test
  void fileStore_whenGrantRecordHasMalformedValue_expectIOException() throws Exception {
    Path root = tempDir.resolve("app-services");
    FileAppServiceGrantStore store = new FileAppServiceGrantStore(root);
    AppServiceGrant grant =
        grant("asg-111111111111111111111111", Instant.parse("2026-05-24T12:00:01Z"));
    store.writeGrant(grant);
    Files.writeString(
        root.resolve("grants").resolve(grant.grantId() + ".properties"),
        """
        version=1
        grantId=asg-111111111111111111111111
        consumerAppId=social-inbox
        providerAppId=trust-graph
        serviceId=trust.score
        scopes=score.read
        contexts=message-author
        purpose=Annotate message authors.
        status=active
        createdAt=2026-05-24T12:00:01Z
        updatedAt=2026-05-24T12:00:01Z
        useCount=not-a-number
        """);

    IOException exception = assertThrows(IOException.class, store::listGrants);

    assertEquals("malformed app-service grant record", exception.getMessage());
  }

  @Test
  void fileStore_whenAuditRecordHasMalformedValue_expectIOException() throws Exception {
    Path root = tempDir.resolve("app-services");
    FileAppServiceGrantStore store = new FileAppServiceGrantStore(root);
    AppServiceAuditEvent event =
        event("ase-111111111111111111111111", Instant.parse("2026-05-24T12:00:01Z"));
    store.appendAuditEvent(event);
    Files.writeString(
        root.resolve("audit").resolve(event.eventId() + ".properties"),
        """
        version=1
        eventId=ase-111111111111111111111111
        timestamp=not-an-instant
        eventType=service_invoked
        status=ok
        reasonCode=invocation_allowed
        """);

    IOException exception = assertThrows(IOException.class, () -> store.listAuditEvents(10));

    assertEquals("malformed app-service audit record", exception.getMessage());
  }

  private static AppServiceGrant grant(String grantId, Instant createdAt) {
    return new AppServiceGrant(
        grantId,
        "social-inbox",
        "trust-graph",
        "trust.score",
        List.of("score.read"),
        List.of("message-author"),
        "Annotate message authors.",
        AppServiceGrantStatus.PENDING,
        createdAt,
        createdAt,
        null,
        null,
        null,
        0,
        null);
  }

  private static AppServiceAuditEvent event(String eventId, Instant timestamp) {
    return new AppServiceAuditEvent(
        eventId,
        timestamp,
        "service_invoked",
        "social-inbox",
        "trust-graph",
        "trust.score",
        "asg-111111111111111111111111",
        "score.read",
        "message-author",
        "ok",
        "invocation_allowed",
        "sha256:abc");
  }

  private static AppServiceAuditEvent event(int index, Instant timestamp) {
    return event(eventId(index), timestamp);
  }

  private static String eventId(int index) {
    String hex = Integer.toHexString(index);
    return "ase-" + "0".repeat(24 - hex.length()) + hex;
  }
}
