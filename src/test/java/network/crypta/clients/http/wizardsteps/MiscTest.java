package network.crypta.clients.http.wizardsteps;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class MiscTest {

  private static final String TAG_INPUT = "input";
  private static final String TAG_LABEL = "label";

  private static final String ATTR_CHECKED = "checked";
  private static final String ATTR_FOR = "for";
  private static final String ATTR_ID = "id";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_VALUE = "value";

  private static final String PARAM_AUTODEPLOY = "autodeploy";
  private static final String ID_AUTODEPLOY_TRUE = "autodeployTrue";
  private static final String ID_AUTODEPLOY_FALSE = "autodeployFalse";

  private static final String CHECKED_ON = "on";

  @TempDir Path tempDir;

  @BeforeEach
  void setUpL10n() {
    new NodeL10n(LANGUAGE.ENGLISH, tempDir.toFile());
  }

  @Test
  void getStep_whenCalled_buildsAutoUpdateFormInputs() {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);
    Misc misc = new Misc(core, config);

    HTTPRequest request = mock(HTTPRequest.class);
    PageHelper helper = mock(PageHelper.class);

    HTMLNode content = new HTMLNode("div");
    HTMLNode form = new HTMLNode("form");
    content.addChild(form);

    List<HTMLNode> infoboxes = new ArrayList<>();
    when(helper.getPageContent(anyString())).thenReturn(content);
    when(helper.addFormChild(content, ".", "miscForm")).thenReturn(form);
    when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode infoboxContent = new HTMLNode("div");
              parent.addChild(infoboxContent);
              infoboxes.add(infoboxContent);
              return infoboxContent;
            });

    misc.getStep(request, helper);

    verify(helper, times(1)).getPageContent(anyString());
    verify(helper, times(1)).addFormChild(content, ".", "miscForm");

    ArgumentCaptor<String> infoboxCategoryCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<HTMLNode> infoboxParentCaptor = ArgumentCaptor.forClass(HTMLNode.class);
    ArgumentCaptor<Boolean> infoboxUniqueCaptor = ArgumentCaptor.forClass(Boolean.class);
    ArgumentCaptor<String> infoboxHeaderCaptor = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<String> infoboxTitleCaptor = ArgumentCaptor.forClass(String.class);
    verify(helper, times(1))
        .getInfobox(
            infoboxCategoryCaptor.capture(),
            infoboxHeaderCaptor.capture(),
            infoboxParentCaptor.capture(),
            infoboxTitleCaptor.capture(),
            infoboxUniqueCaptor.capture());
    assertTrue(
        infoboxCategoryCaptor.getAllValues().stream().allMatch("infobox-normal"::equals)
            && infoboxParentCaptor.getAllValues().stream().allMatch(form::equals)
            && infoboxUniqueCaptor.getAllValues().stream().allMatch(Boolean.FALSE::equals)
            && infoboxHeaderCaptor.getAllValues().stream().allMatch(Objects::nonNull)
            && infoboxTitleCaptor.getAllValues().stream().allMatch(Objects::isNull));

    assertEquals(1, infoboxes.size());
    HTMLNode autoUpdateBox = infoboxes.getFirst();

    List<HTMLNode> autodeployRadios =
        findNodes(
            autoUpdateBox,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "radio".equals(node.getAttribute(ATTR_TYPE))
                    && PARAM_AUTODEPLOY.equals(node.getAttribute(ATTR_NAME)));
    assertEquals(2, autodeployRadios.size());
    Map<String, HTMLNode> autodeployRadiosById =
        autodeployRadios.stream()
            .collect(Collectors.toMap(node -> node.getAttribute(ATTR_ID), Function.identity()));
    assertEquals(Set.of(ID_AUTODEPLOY_TRUE, ID_AUTODEPLOY_FALSE), autodeployRadiosById.keySet());
    assertEquals(
        CHECKED_ON, autodeployRadiosById.get(ID_AUTODEPLOY_TRUE).getAttribute(ATTR_CHECKED));
    assertNull(autodeployRadiosById.get(ID_AUTODEPLOY_FALSE).getAttribute(ATTR_CHECKED));

    Set<String> autoUpdateLabelFors =
        findNodes(autoUpdateBox, node -> TAG_LABEL.equals(node.getName())).stream()
            .map(node -> node.getAttribute(ATTR_FOR))
            .filter(Objects::nonNull)
            .collect(Collectors.toSet());
    assertTrue(autoUpdateLabelFors.containsAll(Set.of(ID_AUTODEPLOY_TRUE, ID_AUTODEPLOY_FALSE)));

    List<HTMLNode> upnpCheckboxes =
        findNodes(
            autoUpdateBox,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "checkbox".equals(node.getAttribute(ATTR_TYPE))
                    && "upnp".equals(node.getAttribute(ATTR_NAME)));
    assertTrue(upnpCheckboxes.isEmpty());

    String expectedBack = NodeL10n.getBase().getString("Toadlet.back");
    String expectedNext = NodeL10n.getBase().getString("Toadlet.next");

    Map<String, String> submitValuesByName =
        findNodes(
                autoUpdateBox,
                node ->
                    TAG_INPUT.equals(node.getName())
                        && "submit".equals(node.getAttribute(ATTR_TYPE)))
            .stream()
            .filter(node -> node.getAttribute(ATTR_NAME) != null)
            .collect(
                Collectors.toMap(
                    node -> node.getAttribute(ATTR_NAME), node -> node.getAttribute(ATTR_VALUE)));
    assertEquals(Set.of("back", "next"), submitValuesByName.keySet());
    assertEquals(expectedBack, submitValuesByName.get("back"));
    assertEquals(expectedNext, submitValuesByName.get("next"));
  }

  @ParameterizedTest
  @CsvSource({"true,true", "TRUE,true", "false,false", "'',false", "notABool,false"})
  void postStep_whenAutodeployValueProvided_parsesBooleanAndReturnsOpenNet(
      String autodeployValue, boolean expectedEnabled) {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);
    Misc misc = spy(new Misc(core, config));

    doNothing().when(misc).setAutoUpdate(anyBoolean());

    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe(PARAM_AUTODEPLOY, 10)).thenReturn(autodeployValue);

    String nextStep = misc.postStep(request);

    verify(misc, times(1)).setAutoUpdate(expectedEnabled);
    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name(), nextStep);
  }

  @Test
  void setAutoUpdate_whenConfigWriteSucceeds_setsAutoupdateOption() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);
    SubConfig updaterConfig = mock(SubConfig.class);
    when(config.get("node.updater")).thenReturn(updaterConfig);

    Misc misc = new Misc(core, config);

    misc.setAutoUpdate(true);

    verify(updaterConfig, times(1)).set("autoupdate", true);
  }

  @Test
  void setAutoUpdate_whenConfigThrowsConfigException_doesNotPropagate() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);
    SubConfig updaterConfig = mock(SubConfig.class);
    when(config.get("node.updater")).thenReturn(updaterConfig);
    doThrow(new InvalidConfigValueException("invalid")).when(updaterConfig).set("autoupdate", true);

    Misc misc = new Misc(core, config);

    assertDoesNotThrow(() -> misc.setAutoUpdate(true));
  }

  @Test
  void setUPnP_whenCalled_isNoOp() {
    NodeClientCore core = mock(NodeClientCore.class);
    Config config = mock(Config.class);
    Misc misc = new Misc(core, config);

    assertDoesNotThrow(() -> misc.setUPnP(true));
    assertDoesNotThrow(() -> misc.setUPnP(false));
    verifyNoInteractions(core);
  }

  private static List<HTMLNode> findNodes(HTMLNode root, Predicate<HTMLNode> predicate) {
    Objects.requireNonNull(root, "root");
    Objects.requireNonNull(predicate, "predicate");

    List<HTMLNode> matches = new ArrayList<>();
    Deque<HTMLNode> stack = new ArrayDeque<>();
    stack.push(root);
    while (!stack.isEmpty()) {
      HTMLNode current = stack.pop();
      if (predicate.test(current)) {
        matches.add(current);
      }
      List<HTMLNode> children = current.getChildren();
      for (int index = children.size() - 1; index >= 0; index--) {
        stack.push(children.get(index));
      }
    }
    return matches;
  }
}
