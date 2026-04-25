package network.crypta.clients.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LegacyAdminSurfaceTest {
  @Test
  void constructor_whenIdBlank_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new LegacyAdminSurface(
                " ",
                "Queue",
                "/downloads/",
                LegacyAdminRetirementState.PRIMARY_REPLACED,
                "/apps/queue-manager/",
                "Queue Manager",
                "notes",
                true,
                false));
  }

  @Test
  void constructor_whenReplacementUrlExternal_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new LegacyAdminSurface(
                "queue",
                "Queue",
                "/downloads/",
                LegacyAdminRetirementState.PRIMARY_REPLACED,
                "https://example.test/apps/queue-manager/",
                "Queue Manager",
                "notes",
                true,
                false));
  }

  @Test
  void constructor_whenReplacementUrlProtocolRelative_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new LegacyAdminSurface(
                "queue",
                "Queue",
                "/downloads/",
                LegacyAdminRetirementState.PRIMARY_REPLACED,
                "//example.test/apps/queue-manager/",
                "Queue Manager",
                "notes",
                true,
                false));
  }

  @Test
  void rendersNotice_whenPrimaryReplacedWithReplacement_expectTrue() {
    LegacyAdminSurface surface =
        new LegacyAdminSurface(
            "queue",
            "Queue",
            "/downloads/",
            LegacyAdminRetirementState.PRIMARY_REPLACED,
            "/apps/queue-manager/",
            "Queue Manager",
            "notes",
            true,
            false);

    assertTrue(surface.rendersNotice());
  }

  @Test
  void rendersNotice_whenPrimaryReplacedWithoutReplacement_expectFalse() {
    LegacyAdminSurface surface =
        new LegacyAdminSurface(
            "queue",
            "Queue",
            "/downloads/",
            LegacyAdminRetirementState.PRIMARY_REPLACED,
            null,
            null,
            "notes",
            true,
            false);

    assertFalse(surface.rendersNotice());
  }

  @Test
  void rendersNotice_whenPendingWithReplacement_expectFalse() {
    LegacyAdminSurface surface =
        new LegacyAdminSurface(
            "wizard",
            "Wizard",
            "/wizard/",
            LegacyAdminRetirementState.PENDING,
            "/app/node/#wizard",
            "Web Shell wizard",
            "notes",
            true,
            false);

    assertFalse(surface.rendersNotice());
  }
}
