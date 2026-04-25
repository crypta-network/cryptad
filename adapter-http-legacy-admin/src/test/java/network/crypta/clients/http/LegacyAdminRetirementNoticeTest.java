package network.crypta.clients.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class LegacyAdminRetirementNoticeTest {
  @Test
  void render_whenSurfacePrimaryReplaced_expectFallbackNoticeWithReplacementLink() {
    String html =
        LegacyAdminRetirementNotice.render(LegacyAdminRetirementRegistry.require("friends"))
            .orElseThrow()
            .generate();

    assertTrue(html.contains("Legacy fallback page"));
    assertTrue(html.contains("This legacy page remains available as a fallback and debug view."));
    assertTrue(html.contains("The primary flow is now in"));
    assertTrue(html.contains("href=\"/app/node/#peers\""));
    assertTrue(html.contains("Web Shell peer control"));
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
        LegacyAdminRetirementNotice.renderPlainText(
                LegacyAdminRetirementRegistry.require("diagnostic"))
            .orElseThrow();

    assertFalse(notice.contains("\r"));
    assertTrue(
        notice.startsWith(
            """
            Legacy fallback page
            This legacy page remains available as a fallback and debug view.
            The primary flow is now in Web Shell diagnostics: /app/node/#diagnostics

            """));
  }
}
