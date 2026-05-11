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
            surface(
                " ",
                "Queue",
                "/downloads/",
                LegacyAdminRetirementState.PRIMARY_REPLACED,
                "/apps/queue-manager/",
                "Queue Manager"));
  }

  @Test
  void constructor_whenReplacementUrlExternal_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            surface(
                "queue",
                "Queue",
                "/downloads/",
                LegacyAdminRetirementState.PRIMARY_REPLACED,
                "https://example.test/apps/queue-manager/",
                "Queue Manager"));
  }

  @Test
  void constructor_whenReplacementUrlProtocolRelative_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            surface(
                "queue",
                "Queue",
                "/downloads/",
                LegacyAdminRetirementState.PRIMARY_REPLACED,
                "//example.test/apps/queue-manager/",
                "Queue Manager"));
  }

  @Test
  void rendersNotice_whenPrimaryReplacedWithReplacement_expectTrue() {
    LegacyAdminSurface surface =
        surface(
            "queue",
            "Queue",
            "/downloads/",
            LegacyAdminRetirementState.PRIMARY_REPLACED,
            "/apps/queue-manager/",
            "Queue Manager");

    assertTrue(surface.rendersNotice());
  }

  @Test
  void rendersNotice_whenPrimaryReplacedRemovedByDefault_expectFalse() {
    LegacyAdminSurface surface =
        new LegacyAdminSurface(
            "queue",
            "Queue",
            "/downloads/",
            LegacyAdminRetirementState.PRIMARY_REPLACED,
            "/apps/queue-manager/",
            "Queue Manager",
            "notes",
            LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT,
            1,
            "phase-6-pr-8",
            "none",
            true,
            false);

    assertFalse(surface.rendersNotice());
  }

  @Test
  void rendersNotice_whenPrimaryReplacedWithoutReplacement_expectFalse() {
    LegacyAdminSurface surface =
        surface(
            "queue",
            "Queue",
            "/downloads/",
            LegacyAdminRetirementState.PRIMARY_REPLACED,
            null,
            null);

    assertFalse(surface.rendersNotice());
  }

  @Test
  void rendersNotice_whenPendingWithReplacement_expectFalse() {
    LegacyAdminSurface surface =
        surface(
            "wizard",
            "Wizard",
            "/wizard/",
            LegacyAdminRetirementState.PENDING,
            "/app/node/#wizard",
            "Web Shell wizard");

    assertFalse(surface.rendersNotice());
  }

  private static LegacyAdminSurface surface(
      String id,
      String title,
      String legacyPath,
      LegacyAdminRetirementState state,
      String replacementUrl,
      String replacementLabel) {
    return new LegacyAdminSurface(
        id,
        title,
        legacyPath,
        state,
        replacementUrl,
        replacementLabel,
        "notes",
        LegacyAdminRemovalMode.RENDER_LEGACY,
        0,
        null,
        "render-legacy",
        true,
        false);
  }
}
