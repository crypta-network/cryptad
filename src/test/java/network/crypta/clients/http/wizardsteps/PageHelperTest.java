package network.crypta.clients.http.wizardsteps;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.ToadletContext;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PageHelperTest {

  private static final String WIZARD_TITLE = "wizard title";
  private static final String INFOBOX_CATEGORY = "infobox-normal";
  private static final String INFOBOX_HEADER = "Header";
  private static final String INFOBOX_TITLE = "Title";

  private static final String TAG_INPUT = "input";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String TYPE_HIDDEN = "hidden";

  private static final String FIELD_PRESET = "preset";
  private static final String FIELD_SINGLESTEP = "singlestep";
  private static final String FIELD_OPENNET = "opennet";
  private static final String FIELD_STEP = "step";

  private static final String FORM_ID = "wizardForm";
  private static final String TARGET_SUBMIT = "/submit";

  @Mock ToadletContext toadletContext;
  @Mock PageMaker pageMaker;
  @Mock PageNode pageNode;

  @Test
  void getPageContent_whenCalled_expectUsesWizardRenderParametersAndReturnsContentNode() {
    PersistFields persistFields = persistFields(false, false, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.WELCOME);

    when(toadletContext.getPageMaker()).thenReturn(pageMaker);

    HTMLNode expectedContentNode = new HTMLNode("div");
    when(pageNode.getContentNode()).thenReturn(expectedContentNode);
    when(pageMaker.getPageNode(
            WIZARD_TITLE,
            toadletContext,
            new RenderParameters().renderNavigationLinks(false).renderStatus(false)))
        .thenReturn(pageNode);

    HTMLNode content = helper.getPageContent(WIZARD_TITLE);

    assertSame(expectedContentNode, content);

    ArgumentCaptor<RenderParameters> captor = ArgumentCaptor.forClass(RenderParameters.class);
    verify(pageMaker)
        .getPageNode(
            org.mockito.ArgumentMatchers.eq(WIZARD_TITLE),
            org.mockito.ArgumentMatchers.eq(toadletContext),
            captor.capture());
    RenderParameters params = captor.getValue();
    assertFalse(params.isRenderNavigationLinks());
    assertFalse(params.isRenderStatus());
    assertTrue(params.isRenderModeSwitch());
  }

  @Test
  void getPageOuter_whenPageNotInitialized_expectThrowsWithHelpfulMessage() {
    PersistFields persistFields = persistFields(false, false, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.WELCOME);

    NullPointerException exception = assertThrows(NullPointerException.class, helper::getPageOuter);

    assertEquals(
        "pageNode was not initialized. getPageContent must be called first.",
        exception.getMessage());
  }

  @Test
  void getPageOuter_whenPageInitialized_expectReturnsOuterNode() {
    PersistFields persistFields = persistFields(false, false, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.WELCOME);

    when(toadletContext.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(
            WIZARD_TITLE,
            toadletContext,
            new RenderParameters().renderNavigationLinks(false).renderStatus(false)))
        .thenReturn(pageNode);

    HTMLNode expectedOuterNode = new HTMLNode("html");
    when(pageNode.getOuterNode()).thenReturn(expectedOuterNode);
    when(pageNode.getContentNode()).thenReturn(new HTMLNode("div"));

    helper.getPageContent(WIZARD_TITLE);
    HTMLNode outer = helper.getPageOuter();

    assertSame(expectedOuterNode, outer);
  }

  @Test
  void generate_whenPageNotInitialized_expectThrowsWithHelpfulMessage() {
    PersistFields persistFields = persistFields(false, false, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.WELCOME);

    NullPointerException exception = assertThrows(NullPointerException.class, helper::generate);

    assertEquals(
        "pageNode was not initialized. getPageContent must be called first.",
        exception.getMessage());
  }

  @Test
  void generate_whenPageInitialized_expectDelegatesToPageNode() {
    PersistFields persistFields = persistFields(false, false, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.WELCOME);

    when(toadletContext.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(
            WIZARD_TITLE,
            toadletContext,
            new RenderParameters().renderNavigationLinks(false).renderStatus(false)))
        .thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(new HTMLNode("div"));
    when(pageNode.generate()).thenReturn("<html>ok</html>");

    helper.getPageContent(WIZARD_TITLE);
    String html = helper.generate();

    assertEquals("<html>ok</html>", html);
    verify(pageNode).generate();
  }

  @Test
  void getInfobox_whenCalled_expectDelegatesToPageMaker() {
    PersistFields persistFields = persistFields(false, false, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.WELCOME);

    when(toadletContext.getPageMaker()).thenReturn(pageMaker);

    HTMLNode parent = new HTMLNode("div");
    HTMLNode expectedInfoboxNode = new HTMLNode("div");
    when(pageMaker.getInfobox(INFOBOX_CATEGORY, INFOBOX_HEADER, parent, INFOBOX_TITLE, true))
        .thenReturn(expectedInfoboxNode);

    HTMLNode infobox =
        helper.getInfobox(INFOBOX_CATEGORY, INFOBOX_HEADER, parent, INFOBOX_TITLE, true);

    assertSame(expectedInfoboxNode, infobox);
    verify(pageMaker).getInfobox(INFOBOX_CATEGORY, INFOBOX_HEADER, parent, INFOBOX_TITLE, true);
  }

  @Test
  void addFormChild_whenPresetSingleStepAndIncludeOpennet_expectPersistsAllFields() {
    PersistFields persistFields = persistFields(true, true, true);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH);

    HTMLNode parent = new HTMLNode("div");
    HTMLNode form = new HTMLNode("form");
    when(toadletContext.addFormChild(parent, TARGET_SUBMIT, FORM_ID)).thenReturn(form);

    HTMLNode returned = helper.addFormChild(parent, TARGET_SUBMIT, FORM_ID, true);

    assertSame(form, returned);
    assertHiddenInputs(
        form,
        Map.of(
            FIELD_PRESET,
            FirstTimeWizardToadlet.WIZARD_PRESET.LOW.name(),
            FIELD_SINGLESTEP,
            "true",
            FIELD_OPENNET,
            "true",
            FIELD_STEP,
            FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH.name()));
  }

  @Test
  void addFormChild_whenNoPresetNoSingleStepAndExcludeOpennet_expectPersistsOnlyStep() {
    PersistFields persistFields = persistFields(false, true, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.OPENNET);

    HTMLNode parent = new HTMLNode("div");
    HTMLNode form = new HTMLNode("form");
    when(toadletContext.addFormChild(parent, ".", FORM_ID)).thenReturn(form);

    HTMLNode returned = helper.addFormChild(parent, ".", FORM_ID, false);

    assertSame(form, returned);
    assertHiddenInputs(form, Map.of(FIELD_STEP, FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name()));
  }

  @Test
  void addFormChild_whenOpennetExcluded_expectDoesNotPersistOpennetButPersistsOthers() {
    PersistFields persistFields = persistFields(true, true, true);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.MISC);

    HTMLNode parent = new HTMLNode("div");
    HTMLNode form = new HTMLNode("form");
    when(toadletContext.addFormChild(parent, TARGET_SUBMIT, FORM_ID)).thenReturn(form);

    HTMLNode returned = helper.addFormChild(parent, TARGET_SUBMIT, FORM_ID, false);

    assertSame(form, returned);
    assertHiddenInputs(
        form,
        Map.of(
            FIELD_PRESET,
            FirstTimeWizardToadlet.WIZARD_PRESET.LOW.name(),
            FIELD_SINGLESTEP,
            "true",
            FIELD_STEP,
            FirstTimeWizardToadlet.WIZARD_STEP.MISC.name()));
  }

  @Test
  void addFormChild_whenUsingDefaultOverload_expectIncludesOpennetField() {
    PersistFields persistFields = persistFields(false, true, false);
    PageHelper helper =
        new PageHelper(toadletContext, persistFields, FirstTimeWizardToadlet.WIZARD_STEP.OPENNET);

    HTMLNode parent = new HTMLNode("div");
    HTMLNode form = new HTMLNode("form");
    when(toadletContext.addFormChild(parent, ".", FORM_ID)).thenReturn(form);

    HTMLNode returned = helper.addFormChild(parent, ".", FORM_ID);

    assertSame(form, returned);
    assertHiddenInputs(
        form,
        Map.of(
            FIELD_OPENNET, "true", FIELD_STEP, FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name()));
  }

  private static PersistFields persistFields(
      boolean hasPreset, boolean opennet, boolean singleStep) {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.hasParameters()).thenReturn(true);
    when(request.getParam(FIELD_PRESET))
        .thenReturn(hasPreset ? FirstTimeWizardToadlet.WIZARD_PRESET.LOW.name() : "");
    when(request.getParam(
            org.mockito.ArgumentMatchers.eq(FIELD_OPENNET),
            org.mockito.ArgumentMatchers.anyString()))
        .thenReturn(String.valueOf(opennet));
    when(request.getParam(
            org.mockito.ArgumentMatchers.eq(FIELD_SINGLESTEP),
            org.mockito.ArgumentMatchers.anyString()))
        .thenReturn(String.valueOf(singleStep));
    return new PersistFields(request);
  }

  private static void assertHiddenInputs(HTMLNode form, Map<String, String> expectedNameToValue) {
    Map<String, String> actualNameToValue = new HashMap<>();
    List<HTMLNode> children = form.getChildren();
    for (HTMLNode child : children) {
      if (!TAG_INPUT.equals(child.getName())
          || !TYPE_HIDDEN.equals(child.getAttribute(ATTR_TYPE))) {
        continue;
      }
      String name = child.getAttribute(ATTR_NAME);
      String value = child.getAttribute(ATTR_VALUE);
      if (actualNameToValue.put(name, value) != null) {
        throw new AssertionError("Duplicate hidden input name=" + name);
      }
    }
    assertEquals(expectedNameToValue, actualNameToValue);
  }
}
