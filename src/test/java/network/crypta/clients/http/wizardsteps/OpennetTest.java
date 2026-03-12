package network.crypta.clients.http.wizardsteps;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OpennetTest {

  private static final String ATTR_CLASS = "class";
  private static final String OPENNET_PART_NAME = "opennet";
  private static final int OPENNET_MAXLEN = 5;
  private static final String TAG_INPUT = "input";

  @Test
  void postStep_whenOpennetSelected_expectRedirectToSecurityNetworkWithPartValue() {
    HTTPRequest request = org.mockito.Mockito.mock(HTTPRequest.class);
    when(request.isPartSet(OPENNET_PART_NAME)).thenReturn(true);
    when(request.getPartAsStringFailsafe(OPENNET_PART_NAME, OPENNET_MAXLEN)).thenReturn("true");

    String redirect = new Opennet().postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK + "&opennet=true", redirect);
    verify(request).isPartSet(OPENNET_PART_NAME);
    verify(request).getPartAsStringFailsafe(OPENNET_PART_NAME, OPENNET_MAXLEN);
  }

  @Test
  void postStep_whenOpennetSelectedButEmptyValue_expectRedirectWithEmptyParam() {
    HTTPRequest request = org.mockito.Mockito.mock(HTTPRequest.class);
    when(request.isPartSet(OPENNET_PART_NAME)).thenReturn(true);
    when(request.getPartAsStringFailsafe(OPENNET_PART_NAME, OPENNET_MAXLEN)).thenReturn("");

    String redirect = new Opennet().postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK + "&opennet=", redirect);
    verify(request).isPartSet(OPENNET_PART_NAME);
    verify(request).getPartAsStringFailsafe(OPENNET_PART_NAME, OPENNET_MAXLEN);
  }

  @Test
  void postStep_whenOpennetNotSelected_expectRedirectBackToOpennetStep() {
    HTTPRequest request = org.mockito.Mockito.mock(HTTPRequest.class);
    when(request.isPartSet(OPENNET_PART_NAME)).thenReturn(false);

    String redirect = new Opennet().postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name(), redirect);
    verify(request).isPartSet(OPENNET_PART_NAME);
    verify(request, never()).getPartAsStringFailsafe(anyString(), anyInt());
  }

  @Test
  void getStep_whenCalled_buildsFormWithExpectedControls() {
    HTTPRequest request = org.mockito.Mockito.mock(HTTPRequest.class);
    PageHelper helper = org.mockito.Mockito.mock(PageHelper.class);

    HTMLNode contentNode = new HTMLNode("div");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n baseL10n = org.mockito.Mockito.mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      stubL10nToEchoKey(baseL10n);

      when(helper.getPageContent(anyString())).thenReturn(contentNode);

      when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(2);
                HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, "infobox");
                parent.addChild(infobox);
                return infobox;
              });

      when(helper.addFormChild(any(HTMLNode.class), anyString(), anyString(), anyBoolean()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(0);
                String id = invocation.getArgument(2);
                HTMLNode form = new HTMLNode("form", "id", id);
                parent.addChild(form);
                return form;
              });

      new Opennet().getStep(request, helper);
    }

    HTMLNode infobox =
        getFirstDescendantOrThrow(
            contentNode,
            node ->
                "div".equals(node.getName()) && "infobox".equals(node.getAttribute(ATTR_CLASS)));
    HTMLNode form = getFirstDescendantOrThrow(infobox, node -> "form".equals(node.getName()));

    List<HTMLNode> radioInputs =
        findDescendants(
            form,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "radio".equals(node.getAttribute("type"))
                    && OPENNET_PART_NAME.equals(node.getAttribute("name")));

    assertEquals(2, radioInputs.size());
    assertTrue(hasInputWith(radioInputs, Map.of("value", "false", "id", "opennetFalse")));
    assertTrue(hasInputWith(radioInputs, Map.of("value", "true", "id", "opennetTrue")));

    assertTrue(
        hasInputWith(
            findDescendants(form, OpennetTest::isInputElement),
            Map.of("type", "submit", "name", "back")));
    assertTrue(
        hasInputWith(
            findDescendants(form, OpennetTest::isInputElement),
            Map.of("type", "submit", "name", "next")));

    HTMLNode footToggleable =
        getFirstDescendantOrThrow(
            infobox,
            node ->
                "div".equals(node.getName()) && "toggleable".equals(node.getAttribute(ATTR_CLASS)));
    HTMLNode orderedList =
        getFirstDescendantOrThrow(footToggleable, node -> "ol".equals(node.getName()));
    long listItems =
        orderedList.getChildren().stream().filter(n -> "li".equals(n.getName())).count();
    assertEquals(10L, listItems);
  }

  @Test
  void getStep_whenCalled_usesExpectedPageHelperWiring() {
    HTTPRequest request = org.mockito.Mockito.mock(HTTPRequest.class);
    PageHelper helper = org.mockito.Mockito.mock(PageHelper.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n baseL10n = org.mockito.Mockito.mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      stubL10nToEchoKey(baseL10n);

      when(helper.getPageContent(anyString())).thenReturn(contentNode);
      when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
          .thenReturn(infoboxNode);
      when(helper.addFormChild(any(HTMLNode.class), anyString(), anyString(), anyBoolean()))
          .thenReturn(formNode);

      new Opennet().getStep(request, helper);
    }

    verify(helper).getPageContent("FirstTimeWizardToadlet.opennetChoicePageTitle");
    verify(helper)
        .getInfobox(
            "infobox-normal",
            "FirstTimeWizardToadlet.opennetChoiceTitle",
            contentNode,
            null,
            false);
    verify(helper).addFormChild(infoboxNode, ".", "opennetForm", false);
  }

  private static void stubL10nToEchoKey(BaseL10n baseL10n) {
    when(baseL10n.getString(anyString()))
        .thenAnswer(invocation -> invocation.getArgument(0, String.class));
    when(baseL10n.getString(anyString(), anyString(), anyString()))
        .thenAnswer(invocation -> invocation.getArgument(0, String.class));
  }

  private static boolean isInputElement(HTMLNode node) {
    return TAG_INPUT.equals(node.getName());
  }

  private static boolean hasInputWith(List<HTMLNode> inputs, Map<String, String> attributes) {
    for (HTMLNode input : inputs) {
      if (!TAG_INPUT.equals(input.getName())) {
        continue;
      }
      boolean allMatch = true;
      for (Map.Entry<String, String> entry : attributes.entrySet()) {
        if (!Objects.equals(entry.getValue(), input.getAttribute(entry.getKey()))) {
          allMatch = false;
          break;
        }
      }
      if (allMatch) {
        return true;
      }
    }
    return false;
  }

  private static List<HTMLNode> findDescendants(HTMLNode root, Predicate<HTMLNode> predicate) {
    List<HTMLNode> matches = new ArrayList<>();
    Deque<HTMLNode> stack = new ArrayDeque<>();
    stack.push(root);

    while (!stack.isEmpty()) {
      HTMLNode node = stack.pop();
      if (predicate.test(node)) {
        matches.add(node);
      }
      List<HTMLNode> children = node.getChildren();
      for (int i = children.size() - 1; i >= 0; i--) {
        stack.push(children.get(i));
      }
    }
    return matches;
  }

  private static HTMLNode getFirstDescendantOrThrow(HTMLNode root, Predicate<HTMLNode> predicate) {
    List<HTMLNode> matches = findDescendants(root, predicate);
    if (matches.isEmpty()) {
      fail("Expected to find matching descendant node, but none was present.");
    }
    HTMLNode node = matches.getFirst();
    assertNotNull(node);
    return node;
  }
}
