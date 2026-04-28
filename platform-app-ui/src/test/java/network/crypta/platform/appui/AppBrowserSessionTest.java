package network.crypta.platform.appui;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppBrowserSessionTest {
  private static final Instant ISSUED_AT = Instant.parse("2026-04-28T10:00:00Z");
  private static final Instant EXPIRES_AT = Instant.parse("2026-04-28T11:00:00Z");

  @Test
  void constructor_whenInputsNeedNormalization_expectTrimmedAppIdAndSortedImmutablePermissions() {
    ArrayList<String> permissions = new ArrayList<>(List.of(" queue.write ", "queue.read"));

    AppBrowserSession session =
        new AppBrowserSession(" demo-app ", permissions, ISSUED_AT, EXPIRES_AT);
    permissions.add("peers.read");

    assertEquals("demo-app", session.appId());
    assertEquals(List.of("queue.read", "queue.write"), session.permissions());
    List<String> exposedPermissions = session.permissions();

    assertThrows(
        UnsupportedOperationException.class, () -> addConfigReadPermission(exposedPermissions));
  }

  @Test
  void constructor_whenIdentityOrExpiryInvalid_expectIllegalArgumentException() {
    List<String> permissions = List.of("queue.read");
    List<String> permissionsWithBlankValue = List.of("queue.read", " ");

    assertThrows(
        IllegalArgumentException.class,
        () -> new AppBrowserSession(" ", permissions, ISSUED_AT, EXPIRES_AT));
    assertThrows(
        IllegalArgumentException.class,
        () -> new AppBrowserSession("demo-app", permissionsWithBlankValue, ISSUED_AT, EXPIRES_AT));
    assertThrows(
        IllegalArgumentException.class,
        () -> new AppBrowserSession("demo-app", permissions, ISSUED_AT, ISSUED_AT));
  }

  @Test
  void toString_whenIssueCarriesRawToken_expectTokenRedacted() {
    AppBrowserSessionIssue issue = new AppBrowserSessionIssue("secret-token", EXPIRES_AT);

    String text = issue.toString();

    assertTrue(text.contains("token=[REDACTED]"));
    assertTrue(text.contains(EXPIRES_AT.toString()));
    assertFalse(text.contains("secret-token"));
  }

  @Test
  void issueConstructor_whenTokenBlank_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> new AppBrowserSessionIssue(" ", EXPIRES_AT));
  }

  private static void addConfigReadPermission(List<String> permissions) {
    permissions.add("config.read");
  }
}
