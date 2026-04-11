package network.crypta.clients.http.bridge.security;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.PasswordFormOptions;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.http.security.PasswordPromptOptions;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class CorePasswordFormPageRendererTest {
  private static final String HIGH_SECURITY_LEVEL = "HIGH";
  private static final String NEXT_REDIRECT = "/next";
  private static final String CHANGED_SECURITY_LEVELS_TARGET = "/changed-after-init/";

  private final CorePasswordFormPageRenderer renderer = new CorePasswordFormPageRenderer();

  @Test
  void generate_whenCalled_matchesLegacySecurityLevelsRendering() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT);

    HTMLNode bridgedContent = new HTMLNode("div");
    HTMLNode legacyContent = new HTMLNode("div");
    HttpShellContainer container = stubContainer();
    HTMLNode legacyForm = legacyContent.addChild("form");
    legacyForm.addAttribute("target", SecurityLevelsToadlet.resolvedPath());
    legacyForm.addAttribute("id", CorePasswordFormPageRenderer.MASTER_PASSWORD_FORM);

    renderer.generate(options, container, bridgedContent);
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT),
        legacyForm,
        legacyContent);

    assertEquals(legacyContent.generate(), bridgedContent.generate());
  }

  @Test
  void generate_whenFirstTimeWizardWithNullOptionals_matchesLegacySecurityLevelsRendering() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, true, false, false, null, null);

    HTMLNode bridgedContent = new HTMLNode("div");
    HTMLNode legacyContent = new HTMLNode("div");
    HttpShellContainer container = stubContainer();
    HTMLNode legacyForm = legacyContent.addChild("form");
    legacyForm.addAttribute("target", FirstTimeWizardToadlet.TOADLET_URL);
    legacyForm.addAttribute("id", CorePasswordFormPageRenderer.MASTER_PASSWORD_FORM);

    renderer.generate(options, container, bridgedContent);
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, true, false, false, null, null), legacyForm, legacyContent);

    assertEquals(legacyContent.generate(), bridgedContent.generate());
  }

  @Test
  void generate_whenOptionsNull_throwsNullPointerException() {
    HttpShellContainer container = stubContainer();
    HTMLNode content = new HTMLNode("div");

    assertThrows(NullPointerException.class, () -> renderer.generate(null, container, content));
  }

  @Test
  void generate_whenContainerNull_throwsNullPointerException() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT);
    HTMLNode content = new HTMLNode("div");

    assertThrows(NullPointerException.class, () -> renderer.generate(options, null, content));
  }

  @Test
  void generate_whenContentNull_throwsNullPointerException() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT);
    HttpShellContainer container = stubContainer();

    assertThrows(NullPointerException.class, () -> renderer.generate(options, container, null));
  }

  @Test
  void generate_whenSecurityLevelsPropertyChangesAfterPathResolution_usesResolvedRoute() {
    HttpShellContainer container = stubContainer();
    String originalProperty = System.getProperty("network.crypta.seclevels.path");
    String resolvedPath = SecurityLevelsToadlet.resolvedPath();
    System.setProperty("network.crypta.seclevels.path", CHANGED_SECURITY_LEVELS_TARGET);

    try {
      HTMLNode bridgedContent = new HTMLNode("div");
      HTMLNode legacyContent = new HTMLNode("div");
      HTMLNode legacyForm = legacyContent.addChild("form");
      legacyForm.addAttribute("target", resolvedPath);
      legacyForm.addAttribute("id", CorePasswordFormPageRenderer.MASTER_PASSWORD_FORM);

      renderer.generate(
          new PasswordPromptOptions(false, false, false, false, null, null),
          container,
          bridgedContent);
      SecurityLevelsToadlet.generatePasswordFormPage(
          new PasswordFormOptions(false, false, false, false, null, null),
          legacyForm,
          legacyContent);

      assertEquals(legacyContent.generate(), bridgedContent.generate());
    } finally {
      if (originalProperty == null) {
        System.clearProperty("network.crypta.seclevels.path");
      } else {
        System.setProperty("network.crypta.seclevels.path", originalProperty);
      }
    }
  }

  private HttpShellContainer stubContainer() {
    HttpShellContainer container = Mockito.mock(HttpShellContainer.class);
    when(container.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              String target = invocation.getArgument(1);
              String id = invocation.getArgument(2);
              HTMLNode form = parent.addChild("form");
              form.addAttribute("target", target);
              form.addAttribute("id", id);
              return form;
            });
    return container;
  }
}
