package network.crypta.clients.http;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LegacyAdminRetirementNoticeTest {
  @Test
  void render_whenSurfacePrimaryReplaced_expectFallbackNoticeWithReplacementLink() {
    String html =
        LegacyAdminRetirementNotice.render(renderLegacySurface()).orElseThrow().generate();

    assertTrue(html.contains("Legacy fallback page"));
    assertTrue(html.contains("This legacy page remains available as a fallback and debug view."));
    assertTrue(html.contains("The primary flow is now in"));
    assertTrue(html.contains("href=\"/app/node/#diagnostics\""));
    assertTrue(html.contains("Web Shell diagnostics"));
  }

  @Test
  void render_whenSurfaceRemovedByDefault_expectNoFallbackNotice() {
    assertFalse(
        LegacyAdminRetirementNotice.render(LegacyAdminRetirementRegistry.require("friends"))
            .isPresent());
  }

  @Test
  void render_whenSurfaceRetained_expectNoNotice() {
    assertFalse(
        LegacyAdminRetirementNotice.render(LegacyAdminRetirementRegistry.require("help"))
            .isPresent());
  }

  @Test
  void renderPlainText_whenSurfacePrimaryReplaced_expectPlainFallbackNotice() {
    String notice =
        LegacyAdminRetirementNotice.renderPlainText(renderLegacySurface()).orElseThrow();

    assertFalse(notice.contains("\r"));
    assertTrue(
        notice.startsWith(
            """
            Legacy fallback page
            This legacy page remains available as a fallback and debug view.
            The primary flow is now in Web Shell diagnostics: /app/node/#diagnostics

            """));
  }

  private static LegacyAdminSurface renderLegacySurface() {
    return new LegacyAdminSurface(
        "diagnostic-fallback",
        "Diagnostic fallback",
        "/diagnostic-fallback/",
        LegacyAdminRetirementState.PRIMARY_REPLACED,
        "/app/node/#diagnostics",
        "Web Shell diagnostics",
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
