package network.crypta.clients.http.wizardsteps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import network.crypta.clients.http.FirstTimeWizardNewToadlet;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.SubConfig;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.StringCallback;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class WelcomeTest {

  private static final String SUBCONFIG_FPROXY = "fproxy";
  private static final String OPTION_JAVASCRIPT_ENABLED = "javascriptEnabled";
  private static final String UNUSED = "unused";
  private static final String TAG_INPUT = "input";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_SELECTED = "selected";
  private static final String PARAM_INCOGNITO = "incognito";

  @Mock private HTTPRequest request;

  @Mock private PageHelper helper;

  @Test
  void getStep_whenJavascriptEnabled_addsRedirectScriptToNewWizard() {
    // Arrange
    Config config = newConfigWithLanguage("en", new String[] {"en", "de"}, LanguageSetBehavior.OK);
    config
        .get(SUBCONFIG_FPROXY)
        .register(
            OPTION_JAVASCRIPT_ENABLED,
            true,
            0,
            false,
            false,
            UNUSED,
            UNUSED,
            BooleanCallback.from(() -> true, ignored -> {}));

    HTMLNode contentNode = new HTMLNode("div");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    stubHelperFormCreation(helper);
    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(false);

    Welcome step = new Welcome(config);

    // Act
    step.getStep(request, helper);

    // Assert
    HTMLNode script = findFirstDirectChildByName(contentNode, "script");
    assertNotNull(script);
    assertEquals("text/javascript", script.getAttribute("type"));

    HTMLNode rawJs = findFirstDirectChildByName(script, "%");
    assertNotNull(rawJs);
    assertEquals(
        "window.location.replace(\"" + FirstTimeWizardNewToadlet.TOADLET_URL + " \");",
        rawJs.getContent());
  }

  @Test
  void getStep_whenJavascriptDisabled_doesNotAddRedirectScript() {
    // Arrange
    Config config = newConfigWithLanguage("en", new String[] {"en", "de"}, LanguageSetBehavior.OK);
    config
        .get(SUBCONFIG_FPROXY)
        .register(
            OPTION_JAVASCRIPT_ENABLED,
            false,
            0,
            false,
            false,
            UNUSED,
            UNUSED,
            BooleanCallback.from(() -> false, ignored -> {}));

    HTMLNode contentNode = new HTMLNode("div");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    stubHelperFormCreation(helper);
    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(false);

    Welcome step = new Welcome(config);

    // Act
    step.getStep(request, helper);

    // Assert
    assertNull(findFirstDirectChildByName(contentNode, "script"));
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void getStep_whenIncognitoParamVaries_propagatesToAllPresetForms(boolean incognito) {
    // Arrange
    Config config = newConfigWithLanguage("en", new String[] {"en", "de"}, LanguageSetBehavior.OK);
    config
        .get(SUBCONFIG_FPROXY)
        .register(
            OPTION_JAVASCRIPT_ENABLED,
            false,
            0,
            false,
            false,
            UNUSED,
            UNUSED,
            BooleanCallback.from(() -> false, ignored -> {}));

    HTMLNode contentNode = new HTMLNode("div");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    stubHelperFormCreation(helper);
    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(incognito);

    Welcome step = new Welcome(config);

    // Act
    step.getStep(request, helper);

    // Assert
    HTMLNode table = findFirstDirectChildByName(contentNode, "table");
    assertNotNull(table);

    List<HTMLNode> forms = findAllByName(table, "form");
    assertEquals(3, forms.size());
    for (HTMLNode form : forms) {
      HTMLNode incognitoInput = findHiddenIncognitoInput(form);
      assertNotNull(incognitoInput);
      assertEquals("hidden", incognitoInput.getAttribute("type"));
      assertEquals(String.valueOf(incognito), incognitoInput.getAttribute(ATTR_VALUE));
    }
  }

  @Test
  void getStep_whenRendered_addsThreePresetFormsWithExpectedSubmitNames() {
    // Arrange
    Config config = newConfigWithLanguage("en", new String[] {"en", "de"}, LanguageSetBehavior.OK);
    config
        .get(SUBCONFIG_FPROXY)
        .register(
            OPTION_JAVASCRIPT_ENABLED,
            false,
            0,
            false,
            false,
            UNUSED,
            UNUSED,
            BooleanCallback.from(() -> false, ignored -> {}));

    HTMLNode contentNode = new HTMLNode("div");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    stubHelperFormCreation(helper);
    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(false);

    Welcome step = new Welcome(config);

    // Act
    step.getStep(request, helper);

    // Assert
    HTMLNode table = findFirstDirectChildByName(contentNode, "table");
    assertNotNull(table);

    List<HTMLNode> submitInputs = findSubmitInputs(table);
    assertEquals(3, submitInputs.size());

    List<String> submitNames = new ArrayList<>();
    for (HTMLNode submit : submitInputs) {
      submitNames.add(submit.getAttribute("name"));
    }
    assertTrue(submitNames.contains("presetLow"));
    assertTrue(submitNames.contains("presetHigh"));
    assertTrue(submitNames.contains("presetNone"));
  }

  @ParameterizedTest
  @CsvSource({"en,en", "de,de"})
  void getStep_whenInitialLanguageVaries_marksMatchingOptionSelected(
      String initialLanguage, String expectedSelectedLanguage) {
    // Arrange
    Config config =
        newConfigWithLanguage(initialLanguage, new String[] {"en", "de"}, LanguageSetBehavior.OK);
    config
        .get(SUBCONFIG_FPROXY)
        .register(
            OPTION_JAVASCRIPT_ENABLED,
            false,
            0,
            false,
            false,
            UNUSED,
            UNUSED,
            BooleanCallback.from(() -> false, ignored -> {}));

    HTMLNode contentNode = new HTMLNode("div");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    stubHelperFormCreation(helper);
    when(request.isParameterSet(PARAM_INCOGNITO)).thenReturn(false);

    Welcome step = new Welcome(config);

    // Act
    step.getStep(request, helper);

    // Assert
    HTMLNode languageForm = findFirstDirectChildByName(contentNode, "form");
    assertNotNull(languageForm);
    assertEquals("languageForm", languageForm.getAttribute("id"));

    HTMLNode select = findFirstDirectChildByName(languageForm, "select");
    assertNotNull(select);
    assertEquals("l10n", select.getAttribute("name"));
    assertEquals("this.form.submit()", select.getAttribute("onchange"));

    List<HTMLNode> options = findAllByName(select, "option");
    assertEquals(2, options.size());
    assertEquals("en", options.get(0).getAttribute(ATTR_VALUE));
    assertEquals("de", options.get(1).getAttribute(ATTR_VALUE));

    HTMLNode selectedOption =
        "en".equals(expectedSelectedLanguage) ? options.get(0) : options.get(1);
    HTMLNode unselectedOption =
        "en".equals(expectedSelectedLanguage) ? options.get(1) : options.get(0);
    assertEquals(expectedSelectedLanguage, selectedOption.getAttribute(ATTR_VALUE));
    assertEquals(ATTR_SELECTED, selectedOption.getAttribute(ATTR_SELECTED));
    assertNull(unselectedOption.getAttribute(ATTR_SELECTED));

    HTMLNode noscript = findFirstDirectChildByName(languageForm, "noscript");
    assertNotNull(noscript);
    HTMLNode submit = findFirstDirectChildByName(noscript, TAG_INPUT);
    assertNotNull(submit);
    assertEquals("submit", submit.getAttribute("type"));
  }

  @Test
  void postStep_whenValidLanguage_setsConfigAndReturnsWelcome() {
    // Arrange
    Config config = newConfigWithLanguage("en", new String[] {"en", "de"}, LanguageSetBehavior.OK);
    Welcome step = new Welcome(config);
    when(request.getPartAsStringFailsafe("l10n", 4096)).thenReturn("de");

    // Act
    String result = step.postStep(request);

    // Assert
    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.WELCOME.name(), result);
    assertEquals("de", config.get("node").getString("l10n"));
    verify(request).getPartAsStringFailsafe("l10n", 4096);
  }

  @Test
  void postStep_whenConfigRejectsLanguage_returnsWelcomeWithoutThrowing() {
    // Arrange
    Config config =
        newConfigWithLanguage("en", new String[] {"en", "de"}, LanguageSetBehavior.INVALID_VALUE);
    Welcome step = new Welcome(config);
    when(request.getPartAsStringFailsafe("l10n", 4096)).thenReturn("de");

    // Act
    String result = step.postStep(request);

    // Assert
    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.WELCOME.name(), result);
    verify(request).getPartAsStringFailsafe("l10n", 4096);
  }

  @Test
  void postStep_whenRestartExceptionThrown_returnsWelcomeWithoutThrowing() {
    // Arrange
    Config config =
        newConfigWithLanguage("en", new String[] {"en", "de"}, LanguageSetBehavior.NEEDS_RESTART);
    Welcome step = new Welcome(config);
    when(request.getPartAsStringFailsafe("l10n", 4096)).thenReturn("de");

    // Act
    String result = step.postStep(request);

    // Assert
    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.WELCOME.name(), result);
    verify(request).getPartAsStringFailsafe("l10n", 4096);
  }

  private enum LanguageSetBehavior {
    OK,
    INVALID_VALUE,
    NEEDS_RESTART
  }

  private static Config newConfigWithLanguage(
      String initialLanguage, String[] possibleLanguages, LanguageSetBehavior behavior) {
    Config config = new Config();

    SubConfig node = config.createSubConfig("node");
    node.register(
        "l10n",
        initialLanguage,
        0,
        false,
        false,
        UNUSED,
        UNUSED,
        new EnumerableStringCallback(possibleLanguages, initialLanguage, behavior));

    config.createSubConfig(SUBCONFIG_FPROXY);

    return config;
  }

  private static final class EnumerableStringCallback extends StringCallback
      implements EnumerableOptionCallback {
    private final String[] possibleValues;
    private final LanguageSetBehavior behavior;
    private String current;

    private EnumerableStringCallback(
        String[] possibleValues, String initialValue, LanguageSetBehavior behavior) {
      this.possibleValues = possibleValues.clone();
      this.current = initialValue;
      this.behavior = behavior;
    }

    @Override
    public String[] getPossibleValues() {
      return possibleValues.clone();
    }

    @Override
    public String get() {
      return current;
    }

    @Override
    public void set(String value) throws InvalidConfigValueException, NodeNeedRestartException {
      if (behavior == LanguageSetBehavior.INVALID_VALUE) {
        throw new InvalidConfigValueException("Rejected for test");
      }
      current = value;
      if (behavior == LanguageSetBehavior.NEEDS_RESTART) {
        throw new NodeNeedRestartException("Restart required for test");
      }
    }
  }

  private static void stubHelperFormCreation(PageHelper helper) {
    doAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              String id = invocation.getArgument(2);
              HTMLNode form = new HTMLNode("form", "id", id);
              parent.addChild(form);
              return form;
            })
        .when(helper)
        .addFormChild(any(HTMLNode.class), anyString(), anyString());
  }

  private static HTMLNode findFirstDirectChildByName(HTMLNode parent, String name) {
    for (HTMLNode child : parent.getChildren()) {
      if (name.equals(child.getName())) {
        return child;
      }
    }
    return null;
  }

  private static List<HTMLNode> findAllByName(HTMLNode root, String tagName) {
    List<HTMLNode> matches = new ArrayList<>();
    Deque<HTMLNode> queue = new ArrayDeque<>();
    queue.add(root);
    while (!queue.isEmpty()) {
      HTMLNode node = queue.removeFirst();
      if (tagName.equals(node.getName())) {
        matches.add(node);
      }
      queue.addAll(node.getChildren());
    }
    return matches;
  }

  private static HTMLNode findHiddenIncognitoInput(HTMLNode formNode) {
    for (HTMLNode input : findAllByName(formNode, TAG_INPUT)) {
      if (PARAM_INCOGNITO.equals(input.getAttribute("name"))) {
        return input;
      }
    }
    return null;
  }

  private static List<HTMLNode> findSubmitInputs(HTMLNode root) {
    List<HTMLNode> matches = new ArrayList<>();
    for (HTMLNode input : findAllByName(root, TAG_INPUT)) {
      if ("submit".equals(input.getAttribute("type"))) {
        matches.add(input);
      }
    }
    return matches;
  }
}
