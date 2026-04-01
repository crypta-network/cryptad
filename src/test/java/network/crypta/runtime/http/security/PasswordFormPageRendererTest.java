package network.crypta.runtime.http.security;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.PasswordFormOptions;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class PasswordFormPageRendererTest {
  private static final String SECURITY_LEVELS_PROPERTY = "network.crypta.seclevels.path";
  private static final String HIGH_SECURITY_LEVEL = "HIGH";
  private static final String NEXT_REDIRECT = "/next";
  private static final String SECURITY_LEVELS_TARGET = "/seclevels/";
  private static final String CHANGED_SECURITY_LEVELS_TARGET = "/changed-after-init/";
  private static final String MASTER_PASSWORD_FORM_ID = "masterPasswordForm";

  @Test
  void generate_whenCalled_matchesLegacySecurityLevelsRendering() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT);

    HTMLNode bridgedContent = new HTMLNode("div");
    HTMLNode legacyContent = new HTMLNode("div");
    HttpShellContainer container = stubContainer();
    HTMLNode legacyForm = legacyContent.addChild("form");
    legacyForm.addAttribute("target", SECURITY_LEVELS_TARGET);
    legacyForm.addAttribute("id", MASTER_PASSWORD_FORM_ID);

    PasswordFormPageRenderer.generate(options, container, SECURITY_LEVELS_TARGET, bridgedContent);
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
    legacyForm.addAttribute("id", MASTER_PASSWORD_FORM_ID);

    PasswordFormPageRenderer.generate(options, container, SECURITY_LEVELS_TARGET, bridgedContent);
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, true, false, false, null, null), legacyForm, legacyContent);

    assertEquals(legacyContent.generate(), bridgedContent.generate());
  }

  @Test
  void generate_whenOptionsNull_throwsNullPointerException() {
    HttpShellContainer container = stubContainer();
    HTMLNode content = new HTMLNode("div");

    assertThrows(
        NullPointerException.class,
        () -> PasswordFormPageRenderer.generate(null, container, SECURITY_LEVELS_TARGET, content));
  }

  @Test
  void generate_whenContainerNull_throwsNullPointerException() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT);
    HTMLNode content = new HTMLNode("div");

    assertThrows(
        NullPointerException.class,
        () -> PasswordFormPageRenderer.generate(options, null, SECURITY_LEVELS_TARGET, content));
  }

  @Test
  void generate_whenSecurityLevelsPathNull_throwsNullPointerException() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT);
    HttpShellContainer container = stubContainer();
    HTMLNode content = new HTMLNode("div");

    assertThrows(
        NullPointerException.class,
        () -> PasswordFormPageRenderer.generate(options, container, null, content));
  }

  @Test
  void generate_whenContentNull_throwsNullPointerException() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, HIGH_SECURITY_LEVEL, NEXT_REDIRECT);
    HttpShellContainer container = stubContainer();

    assertThrows(
        NullPointerException.class,
        () -> PasswordFormPageRenderer.generate(options, container, SECURITY_LEVELS_TARGET, null));
  }

  @Test
  void resolvedSecurityLevelsPath_whenPropertyChangesAfterResolution_returnsCachedRoute() {
    String originalProperty = System.getProperty(SECURITY_LEVELS_PROPERTY);
    String resolvedPath = PasswordFormPageRenderer.resolvedSecurityLevelsPath();

    System.setProperty(SECURITY_LEVELS_PROPERTY, CHANGED_SECURITY_LEVELS_TARGET);

    try {
      assertEquals(resolvedPath, PasswordFormPageRenderer.resolvedSecurityLevelsPath());
      assertEquals(resolvedPath, SecurityLevelsToadlet.resolvedPath());
    } finally {
      if (originalProperty == null) {
        System.clearProperty(SECURITY_LEVELS_PROPERTY);
      } else {
        System.setProperty(SECURITY_LEVELS_PROPERTY, originalProperty);
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
