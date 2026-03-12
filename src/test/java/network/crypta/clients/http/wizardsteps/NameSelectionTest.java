package network.crypta.clients.http.wizardsteps;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NameSelectionTest {

  @TempDir Path tempDir;

  private static final String CONFIG_NODE = "node";
  private static final String CONFIG_KEY_NAME = "name";
  private static final String PART_NNAME = "nname";
  private static final int NNAME_MAXLEN = 128;
  private static final String TAG_INPUT = "input";
  private static final String ATTR_NAME = "name";
  private static final String VALUE_NODE123 = "node123";

  @BeforeEach
  void setupL10n() {
    // Force a deterministic language regardless of the host default Locale.
    new NodeL10n(LANGUAGE.ENGLISH, tempDir.toFile());
  }

  @Test
  void getStep_whenInvoked_expectFormContainsNameInputAndNavigationButtons() {
    Config config = mock(Config.class);
    NameSelection step = new NameSelection(config);

    HTTPRequest request = mock(HTTPRequest.class);
    PageHelper helper = mock(PageHelper.class);

    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");

    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    when(helper.getInfobox(
            eq("infobox-normal"), anyString(), same(contentNode), isNull(), eq(false)))
        .thenReturn(infoboxNode);
    when(helper.addFormChild(same(infoboxNode), eq("."), eq("nnameForm"))).thenReturn(formNode);

    step.getStep(request, helper);

    verify(helper).getPageContent(anyString());
    verify(helper)
        .getInfobox(eq("infobox-normal"), anyString(), same(contentNode), isNull(), eq(false));
    verify(helper).addFormChild(same(infoboxNode), eq("."), eq("nnameForm"));

    assertTrue(
        containsInputWithName(formNode, PART_NNAME),
        "Expected a node-name <input name=\"nname\"> within the step form");
    assertTrue(
        containsInputWithName(formNode, "back"),
        "Expected a back submit button within the step form");
    assertTrue(
        containsInputWithName(formNode, "next"),
        "Expected a next submit button within the step form");
  }

  @Test
  void postStep_whenBlankName_expectRedirectsToSameStepAndDoesNotWriteConfig() {
    Config config = mock(Config.class);
    NameSelection step = new NameSelection(config);

    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe(PART_NNAME, NNAME_MAXLEN)).thenReturn("");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(request).getPartAsStringFailsafe(PART_NNAME, NNAME_MAXLEN);
    verifyNoInteractions(config);
  }

  @ParameterizedTest
  @ValueSource(strings = {"node123", " ", "name-with-dash"})
  void postStep_whenNonEmptyName_expectWritesConfigAndRedirectsToDatastoreSize(String selectedName)
      throws Exception {
    Config config = mock(Config.class);
    SubConfig node = mock(SubConfig.class);
    when(config.get(CONFIG_NODE)).thenReturn(node);

    NameSelection step = new NameSelection(config);

    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe(PART_NNAME, NNAME_MAXLEN)).thenReturn(selectedName);

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.DATASTORE_SIZE.name(), next);
    verify(request).getPartAsStringFailsafe(PART_NNAME, NNAME_MAXLEN);
    verify(config).get(CONFIG_NODE);
    verify(node).set(CONFIG_KEY_NAME, selectedName);
  }

  @Test
  void postStep_whenConfigSetThrows_expectStillRedirectsToDatastoreSize() throws Exception {
    Config config = mock(Config.class);
    SubConfig node = mock(SubConfig.class);
    when(config.get(CONFIG_NODE)).thenReturn(node);

    doThrow(new InvalidConfigValueException("boom")).when(node).set(CONFIG_KEY_NAME, VALUE_NODE123);

    NameSelection step = new NameSelection(config);

    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe(PART_NNAME, NNAME_MAXLEN)).thenReturn(VALUE_NODE123);

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.DATASTORE_SIZE.name(), next);
    verify(request).getPartAsStringFailsafe(PART_NNAME, NNAME_MAXLEN);
    verify(config).get(CONFIG_NODE);
    verify(node).set(CONFIG_KEY_NAME, VALUE_NODE123);
  }

  private static boolean containsInputWithName(HTMLNode root, String attributeValue) {
    for (HTMLNode node : breadthFirst(root)) {
      if (!TAG_INPUT.equals(node.getName())) {
        continue;
      }
      if (attributeValue.equals(node.getAttribute(ATTR_NAME))) {
        return true;
      }
    }
    return false;
  }

  private static List<HTMLNode> breadthFirst(HTMLNode root) {
    assertNotNull(root);
    Deque<HTMLNode> queue = new ArrayDeque<>();
    queue.add(root);

    List<HTMLNode> visited = new ArrayList<>();
    while (!queue.isEmpty()) {
      HTMLNode current = queue.removeFirst();
      visited.add(current);
      queue.addAll(current.getChildren());
    }
    return visited;
  }
}
