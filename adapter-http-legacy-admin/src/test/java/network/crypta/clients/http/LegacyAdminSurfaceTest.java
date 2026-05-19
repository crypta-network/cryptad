package network.crypta.clients.http;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
  void constructor_whenExplicitChildrenWithoutExplicitScope_expectIllegalArgumentException() {
    List<String> explicitChildPaths = List.of("/downloads/listKeys.txt");

    assertThrows(
        IllegalArgumentException.class,
        () ->
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
                LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
                0,
                explicitChildPaths,
                true,
                true,
                false));
  }

  @Test
  void constructor_whenScopeExpandedInWaveNegative_expectIllegalArgumentException() {
    List<String> explicitChildPaths = List.of();

    assertThrows(
        IllegalArgumentException.class,
        () ->
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
                LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
                -1,
                explicitChildPaths,
                true,
                true,
                false));
  }

  @Test
  void constructor_whenExplicitChildPathProtocolRelative_expectIllegalArgumentException() {
    List<String> explicitChildPaths = List.of("//example.test/listKeys.txt");

    assertThrows(
        IllegalArgumentException.class,
        () ->
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
                LegacyAdminRemovalScope.EXPLICIT_CHILDREN,
                2,
                explicitChildPaths,
                true,
                true,
                false));
  }

  @Test
  void constructor_whenExplicitChildrenSourceMutated_expectDefensiveCopy() {
    ArrayList<String> childPaths = new ArrayList<>();
    childPaths.add("/downloads/listKeys.txt");

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
            LegacyAdminRemovalScope.EXPLICIT_CHILDREN,
            2,
            childPaths,
            true,
            true,
            false);

    childPaths.add("/downloads/countRequests.html");

    assertEquals(List.of("/downloads/listKeys.txt"), surface.explicitRemovalChildPaths());
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
            LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
            0,
            List.of(),
            true,
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
        LegacyAdminRemovalScope.CANONICAL_AND_SLASHLESS_ALIAS,
        0,
        List.of(),
        true,
        true,
        false);
  }
}
