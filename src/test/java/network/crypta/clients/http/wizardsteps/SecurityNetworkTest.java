package network.crypta.clients.http.wizardsteps;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SecurityNetworkTest {

  private static final String TAG_INPUT = "input";
  private static final String TAG_DIV = "div";
  private static final String TAG_FORM = "form";

  private static final String ATTR_CLASS = "class";
  private static final String ATTR_ID = "id";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_VALUE = "value";

  private static final String PARAM_CONFIRM = "confirm";
  private static final String PARAM_OPENNET = "opennet";

  private static final String PART_PRESET = "preset";
  private static final String PART_RETURN_FROM_CONFIRM = "return-from-confirm";

  private static final String PART_NETWORK_THREAT_LEVEL = "security-levels.networkThreatLevel";
  private static final String PART_NETWORK_THREAT_LEVEL_CONFIRM =
      "security-levels.networkThreatLevel.confirm";
  private static final String PART_NETWORK_THREAT_LEVEL_TRY_CONFIRM =
      "security-levels.networkThreatLevel.tryConfirm";

  private static final String VALUE_FALSE = "false";

  private static final String CLASS_INFOBOX = "infobox";
  private static final String L10N_SECURITY_OPENNET_FRIENDS_WARNING =
      "SecurityLevels.networkThreatLevel.opennetFriendsWarning";

  @Test
  void setThreatLevel_whenCalled_updatesSecurityLevelsAndStoresConfig() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    when(core.getNode()).thenReturn(node);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);

    SecurityNetwork step = new SecurityNetwork(core);

    step.setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);

    verify(core, times(1)).getNode();
    verify(node, times(1)).services();
    verify(securityLevels, times(1)).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
    verify(core, times(1)).storeConfig();
  }

  @Test
  void postStep_whenThreatLevelPartMissing_expectRedirectToSecurityNetwork() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn("LOW");
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL)).thenReturn(false);

    String redirect = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK.name(), redirect);
    verify(step, never()).setThreatLevel(any(SecurityLevels.NETWORK_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenThreatLevelIsInvalid_expectRedirectToSecurityNetwork() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn("not-a-level");

    String redirect = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK.name(), redirect);
    verify(step, never()).setThreatLevel(any(SecurityLevels.NETWORK_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenReturnFromConfirmWithoutPreset_expectRedisplaySecurityNetwork() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn("HIGH");
    when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL)).thenReturn(true);
    when(request.isPartSet(PART_RETURN_FROM_CONFIRM)).thenReturn(true);

    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PART_PRESET, 4)).thenReturn("");

    String redirect = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK.name(), redirect);
    verify(step, never()).setThreatLevel(any(SecurityLevels.NETWORK_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenReturnFromConfirmWithPreset_expectRedirectToPreviousStep() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn("HIGH");
    when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL)).thenReturn(true);
    when(request.isPartSet(PART_RETURN_FROM_CONFIRM)).thenReturn(true);

    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PART_PRESET, 4)).thenReturn("HIGH");

    String redirect = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.WELCOME.name(), redirect);
    verify(step, never()).setThreatLevel(any(SecurityLevels.NETWORK_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenHighWithoutConfirm_expectRedirectToConfirmationPage() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn("HIGH");
    when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL)).thenReturn(true);
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PART_PRESET, 4)).thenReturn("");

    String redirect = step.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK.name()
            + "&confirm=true&security-levels.networkThreatLevel=HIGH",
        redirect);
    verify(step, never()).setThreatLevel(any(SecurityLevels.NETWORK_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenHighTryConfirmWithoutConfirm_expectRedirectToConfirmationPage() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn("HIGH");
    when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL)).thenReturn(true);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL_TRY_CONFIRM)).thenReturn(true);
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PART_PRESET, 4)).thenReturn("");

    String redirect = step.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK.name()
            + "&confirm=true&security-levels.networkThreatLevel=HIGH",
        redirect);
    verify(step, never()).setThreatLevel(any(SecurityLevels.NETWORK_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenHighConfirmed_expectSetThreatLevelAndRedirectPhysical() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    when(core.getNode()).thenReturn(node);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);

    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn("HIGH");
    when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL)).thenReturn(true);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL_CONFIRM)).thenReturn(true);
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PART_PRESET, 4)).thenReturn("");

    String redirect = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), redirect);
    verify(securityLevels, times(1)).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.HIGH);
    verify(core, times(1)).storeConfig();
  }

  @ParameterizedTest
  @EnumSource(
      value = SecurityLevels.NETWORK_THREAT_LEVEL.class,
      names = {"LOW", "NORMAL"})
  void postStep_whenThreatLevelDoesNotRequireConfirmation_expectSetThreatLevelAndRedirectPhysical(
      SecurityLevels.NETWORK_THREAT_LEVEL level) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    when(core.getNode()).thenReturn(node);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);

    SecurityNetwork step = spy(new SecurityNetwork(core));
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe(PART_NETWORK_THREAT_LEVEL, 128)).thenReturn(level.name());
    when(request.isPartSet(anyString())).thenReturn(false);
    when(request.isPartSet(PART_NETWORK_THREAT_LEVEL)).thenReturn(true);
    when(request.hasParameters()).thenReturn(false);
    when(request.getPartAsStringFailsafe(PART_PRESET, 4)).thenReturn("");

    String redirect = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), redirect);
    verify(securityLevels, times(1)).setThreatLevel(level);
    verify(core, times(1)).storeConfig();
  }

  @Test
  void getStep_whenOpennetTrue_buildsRadioOptionsForOpennetThreatLevels() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = new SecurityNetwork(core);

    HTTPRequest request = mock(HTTPRequest.class);
    PageHelper helper = mock(PageHelper.class);

    HTMLNode contentNode = new HTMLNode("div");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      stubL10nToEchoKey(baseL10n);

      when(request.getParam(PARAM_OPENNET, VALUE_FALSE)).thenReturn("true");
      when(request.isParameterSet(PARAM_CONFIRM)).thenReturn(false);

      when(helper.getPageContent(anyString())).thenReturn(contentNode);
      when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(2);
                HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, CLASS_INFOBOX);
                parent.addChild(infobox);
                return infobox;
              });
      when(helper.addFormChild(any(HTMLNode.class), anyString(), anyString()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(0);
                String id = invocation.getArgument(2);
                HTMLNode form = new HTMLNode(TAG_FORM, ATTR_ID, id);
                parent.addChild(form);
                return form;
              });

      step.getStep(request, helper);
    }

    HTMLNode form = getFirstDescendantOrThrow(contentNode, node -> TAG_FORM.equals(node.getName()));
    HTMLNode choicesDiv =
        getFirstDescendantOrThrow(
            form,
            node ->
                TAG_DIV.equals(node.getName())
                    && "opennetDiv".equals(node.getAttribute(ATTR_CLASS)));

    List<HTMLNode> radios =
        findDescendants(
            choicesDiv,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "radio".equals(node.getAttribute(ATTR_TYPE))
                    && PART_NETWORK_THREAT_LEVEL.equals(node.getAttribute(ATTR_NAME)));

    SecurityLevels.NETWORK_THREAT_LEVEL[] expectedLevels =
        SecurityLevels.NETWORK_THREAT_LEVEL.getOpennetValues();
    assertEquals(expectedLevels.length, radios.size());
    assertTrue(
        radios.stream()
            .map(node -> node.getAttribute(ATTR_VALUE))
            .filter(Objects::nonNull)
            .collect(Collectors.toSet())
            .containsAll(enumNames(expectedLevels)));
    assertTrue(
        radios.stream()
            .map(node -> node.getAttribute(ATTR_ID))
            .filter(Objects::nonNull)
            .collect(Collectors.toSet())
            .containsAll(enumIds(expectedLevels)));

    assertNotNull(findSubmitInput(form, "back"));
    assertNotNull(findSubmitInput(form, "next"));
  }

  @Test
  void getStep_whenOpennetFalse_buildsRadioOptionsForDarknetThreatLevelsAndWarning() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = new SecurityNetwork(core);

    HTTPRequest request = mock(HTTPRequest.class);
    PageHelper helper = mock(PageHelper.class);

    HTMLNode contentNode = new HTMLNode("div");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      stubL10nToEchoKey(baseL10n);

      when(request.getParam(PARAM_OPENNET, VALUE_FALSE)).thenReturn(VALUE_FALSE);
      when(request.isParameterSet(PARAM_CONFIRM)).thenReturn(false);

      when(helper.getPageContent(anyString())).thenReturn(contentNode);
      when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(2);
                HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, CLASS_INFOBOX);
                parent.addChild(infobox);
                return infobox;
              });
      when(helper.addFormChild(any(HTMLNode.class), anyString(), anyString()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(0);
                String id = invocation.getArgument(2);
                HTMLNode form = new HTMLNode(TAG_FORM, ATTR_ID, id);
                parent.addChild(form);
                return form;
              });

      step.getStep(request, helper);
    }

    HTMLNode form = getFirstDescendantOrThrow(contentNode, node -> TAG_FORM.equals(node.getName()));
    HTMLNode choicesDiv =
        getFirstDescendantOrThrow(
            form,
            node ->
                TAG_DIV.equals(node.getName())
                    && "darknetDiv".equals(node.getAttribute(ATTR_CLASS)));

    List<HTMLNode> radios =
        findDescendants(
            choicesDiv,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "radio".equals(node.getAttribute(ATTR_TYPE))
                    && PART_NETWORK_THREAT_LEVEL.equals(node.getAttribute(ATTR_NAME)));

    SecurityLevels.NETWORK_THREAT_LEVEL[] expectedLevels =
        SecurityLevels.NETWORK_THREAT_LEVEL.getDarknetValues();
    assertEquals(expectedLevels.length, radios.size());
    assertTrue(
        radios.stream()
            .map(node -> node.getAttribute(ATTR_VALUE))
            .filter(Objects::nonNull)
            .collect(Collectors.toSet())
            .containsAll(enumNames(expectedLevels)));

    HTMLNode warningBold =
        getFirstDescendantOrThrow(form, node -> "b".equals(node.getName()) && hasTextChild(node));
    assertNotNull(warningBold);
  }

  @Test
  void getStep_whenConfirmHigh_buildsConfirmationFormWithExpectedInputs() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = new SecurityNetwork(core);

    HTTPRequest request = mock(HTTPRequest.class);
    PageHelper helper = mock(PageHelper.class);

    HTMLNode contentNode = new HTMLNode("div");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      stubL10nToEchoKey(baseL10n);

      when(request.isParameterSet(PARAM_CONFIRM)).thenReturn(true);
      when(request.getParam(PARAM_OPENNET, VALUE_FALSE)).thenReturn(VALUE_FALSE);
      when(request.getParam(PART_NETWORK_THREAT_LEVEL)).thenReturn("HIGH");

      when(helper.getPageContent(anyString())).thenReturn(contentNode);
      when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(2);
                HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, CLASS_INFOBOX);
                parent.addChild(infobox);
                return infobox;
              });
      when(helper.addFormChild(any(HTMLNode.class), anyString(), anyString()))
          .thenAnswer(
              invocation -> {
                HTMLNode parent = invocation.getArgument(0);
                String id = invocation.getArgument(2);
                HTMLNode form = new HTMLNode(TAG_FORM, ATTR_ID, id);
                parent.addChild(form);
                return form;
              });

      step.getStep(request, helper);
    }

    HTMLNode form = getFirstDescendantOrThrow(contentNode, node -> TAG_FORM.equals(node.getName()));

    HTMLNode threatLevelHidden =
        getFirstDescendantOrThrow(
            form,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "hidden".equals(node.getAttribute(ATTR_TYPE))
                    && PART_NETWORK_THREAT_LEVEL.equals(node.getAttribute(ATTR_NAME)));
    assertEquals("HIGH", threatLevelHidden.getAttribute(ATTR_VALUE));

    HTMLNode tryConfirmHidden =
        getFirstDescendantOrThrow(
            form,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "hidden".equals(node.getAttribute(ATTR_TYPE))
                    && PART_NETWORK_THREAT_LEVEL_TRY_CONFIRM.equals(node.getAttribute(ATTR_NAME)));
    assertEquals("on", tryConfirmHidden.getAttribute(ATTR_VALUE));

    HTMLNode checkbox =
        getFirstDescendantOrThrow(
            form,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "checkbox".equals(node.getAttribute(ATTR_TYPE))
                    && PART_NETWORK_THREAT_LEVEL_CONFIRM.equals(node.getAttribute(ATTR_NAME)));
    assertEquals("off", checkbox.getAttribute(ATTR_VALUE));

    assertNotNull(findSubmitInput(form, PART_RETURN_FROM_CONFIRM));
    assertNotNull(findSubmitInput(form, "next"));
  }

  @Test
  void getStep_whenCalled_usesExpectedPageHelperWiring() {
    NodeClientCore core = mock(NodeClientCore.class);
    SecurityNetwork step = new SecurityNetwork(core);

    HTTPRequest request = mock(HTTPRequest.class);
    PageHelper helper = mock(PageHelper.class);

    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      stubL10nToEchoKey(baseL10n);

      when(request.getParam(PARAM_OPENNET, VALUE_FALSE)).thenReturn("true");
      when(request.isParameterSet(PARAM_CONFIRM)).thenReturn(false);

      when(helper.getPageContent(anyString())).thenReturn(contentNode);
      when(helper.getInfobox(anyString(), anyString(), any(HTMLNode.class), any(), anyBoolean()))
          .thenReturn(infoboxNode);
      when(helper.addFormChild(any(HTMLNode.class), anyString(), anyString())).thenReturn(formNode);

      step.getStep(request, helper);
    }

    verify(helper).getPageContent("FirstTimeWizardToadlet.networkSecurityPageTitle");
    verify(helper)
        .getInfobox(
            "infobox-normal",
            "FirstTimeWizardToadlet.networkThreatLevelHeaderOpennet",
            contentNode,
            null,
            false);
    verify(helper).addFormChild(infoboxNode, ".", "networkSecurityForm");
  }

  private static void stubL10nToEchoKey(BaseL10n baseL10n) {
    when(baseL10n.getString(anyString()))
        .thenAnswer(invocation -> invocation.getArgument(0, String.class));
  }

  private static HTMLNode findSubmitInput(HTMLNode root, String name) {
    List<HTMLNode> matches =
        findDescendants(
            root,
            node ->
                TAG_INPUT.equals(node.getName())
                    && "submit".equals(node.getAttribute(ATTR_TYPE))
                    && name.equals(node.getAttribute(ATTR_NAME)));
    if (matches.isEmpty()) {
      return null;
    }
    return matches.getFirst();
  }

  private static boolean hasTextChild(HTMLNode node) {
    for (HTMLNode child : node.getChildren()) {
      if ("#".equals(child.getName())
          && L10N_SECURITY_OPENNET_FRIENDS_WARNING.equals(child.getContent())) {
        return true;
      }
    }
    return false;
  }

  private static Set<String> enumNames(SecurityLevels.NETWORK_THREAT_LEVEL[] values) {
    Set<String> names = new HashSet<>();
    for (SecurityLevels.NETWORK_THREAT_LEVEL value : values) {
      names.add(value.name());
    }
    return names;
  }

  private static Set<String> enumIds(SecurityLevels.NETWORK_THREAT_LEVEL[] values) {
    Set<String> ids = new HashSet<>();
    for (SecurityLevels.NETWORK_THREAT_LEVEL value : values) {
      ids.add(PART_NETWORK_THREAT_LEVEL + value.name());
    }
    return ids;
  }

  private static List<HTMLNode> findDescendants(HTMLNode root, Predicate<HTMLNode> predicate) {
    List<HTMLNode> matches = new ArrayList<>();
    Deque<HTMLNode> queue = new ArrayDeque<>();
    queue.add(root);
    while (!queue.isEmpty()) {
      HTMLNode node = queue.removeFirst();
      if (predicate.test(node)) {
        matches.add(node);
      }
      queue.addAll(node.getChildren());
    }
    return matches;
  }

  private static HTMLNode getFirstDescendantOrThrow(HTMLNode root, Predicate<HTMLNode> predicate) {
    Deque<HTMLNode> queue = new ArrayDeque<>();
    queue.add(root);
    while (!queue.isEmpty()) {
      HTMLNode node = queue.removeFirst();
      if (predicate.test(node)) {
        return node;
      }
      queue.addAll(node.getChildren());
    }
    throw new AssertionError("Could not find expected node in HTML tree.");
  }
}
