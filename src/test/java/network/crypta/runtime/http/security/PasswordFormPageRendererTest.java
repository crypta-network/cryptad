package network.crypta.runtime.http.security;

import network.crypta.clients.http.PasswordFormOptions;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.clients.http.ToadletContainer;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class PasswordFormPageRendererTest {

  @Test
  void generate_whenCalled_matchesLegacySecurityLevelsRendering() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, "HIGH", "/next");

    HTMLNode bridgedContent = new HTMLNode("div");
    HTMLNode legacyContent = new HTMLNode("div");
    ToadletContainer container = stubContainer();

    PasswordFormPageRenderer.generate(options, container, bridgedContent);
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, false, false, true, "HIGH", "/next"),
        container,
        legacyContent);

    assertEquals(legacyContent.generate(), bridgedContent.generate());
  }

  @Test
  void generate_whenFirstTimeWizardWithNullOptionals_matchesLegacySecurityLevelsRendering() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, true, false, false, null, null);

    HTMLNode bridgedContent = new HTMLNode("div");
    HTMLNode legacyContent = new HTMLNode("div");
    ToadletContainer container = stubContainer();

    PasswordFormPageRenderer.generate(options, container, bridgedContent);
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, true, false, false, null, null), container, legacyContent);

    assertEquals(legacyContent.generate(), bridgedContent.generate());
  }

  @Test
  void generate_whenOptionsNull_throwsNullPointerException() {
    ToadletContainer container = stubContainer();
    HTMLNode content = new HTMLNode("div");

    assertThrows(
        NullPointerException.class,
        () -> PasswordFormPageRenderer.generate(null, container, content));
  }

  @Test
  void generate_whenContainerNull_throwsNullPointerException() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, "HIGH", "/next");
    HTMLNode content = new HTMLNode("div");

    assertThrows(
        NullPointerException.class,
        () -> PasswordFormPageRenderer.generate(options, null, content));
  }

  @Test
  void generate_whenContentNull_throwsNullPointerException() {
    PasswordPromptOptions options =
        new PasswordPromptOptions(false, false, false, true, "HIGH", "/next");
    ToadletContainer container = stubContainer();

    assertThrows(
        NullPointerException.class,
        () -> PasswordFormPageRenderer.generate(options, container, null));
  }

  private ToadletContainer stubContainer() {
    ToadletContainer container = Mockito.mock(ToadletContainer.class);
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
