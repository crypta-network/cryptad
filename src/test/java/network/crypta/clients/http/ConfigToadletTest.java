package network.crypta.clients.http;

import java.io.File;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.config.Config;
import network.crypta.config.ConfigCallback;
import network.crypta.config.DirectorySelectionCallback;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.StringCallback;
import network.crypta.config.StringOption;
import network.crypta.config.SubConfig;
import network.crypta.config.WrapperConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.ProgramDirectory;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ConfigToadletTest {
  private static final URI CONFIG_URI = URI.create("http://localhost/config/");
  private static final String WRAPPER_MAX_MEMORY = "wrapper.java.maxmemory";

  @Mock private SubConfig subConfig;
  @Mock private Config config;
  @Mock private ConfigPort configPort;
  @Mock private TransferAccessPort transferAccessPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private ToadletContext ctx;
  @Mock private PageMaker pageMaker;
  @Mock private UserAlertManager alertManager;

  @BeforeEach
  void setUp() {
    new NodeL10n();
  }

  private ConfigToadlet createToadlet() {
    return new ConfigToadlet(
        config,
        subConfig,
        new ConfigToadletRuntimePorts(configPort, transferAccessPort, lifecyclePort));
  }

  @Test
  void addTextBox_whenEnabled_setsExpectedAttributes() {
    Option<?> option = org.mockito.Mockito.mock(Option.class);
    when(option.getShortDesc()).thenReturn("short");

    HTMLNode textBox = ConfigToadlet.addTextBox("value", "prefix.option", option, false);

    assertEquals("input", textBox.getName());
    assertEquals("text", textBox.getAttribute("type"));
    assertEquals("config", textBox.getAttribute("class"));
    assertEquals("short", textBox.getAttribute("alt"));
    assertEquals("prefix.option", textBox.getAttribute("name"));
    assertEquals("value", textBox.getAttribute("value"));
    assertNull(textBox.getAttribute("disabled"));
  }

  @Test
  void addTextBox_whenDisabled_marksDisabled() {
    Option<?> option = org.mockito.Mockito.mock(Option.class);
    when(option.getShortDesc()).thenReturn("short desc");

    HTMLNode textBox = ConfigToadlet.addTextBox("abc", "config.full", option, true);

    assertEquals("disabled", textBox.getAttribute("disabled"));
    assertEquals("abc", textBox.getAttribute("value"));
  }

  @Test
  void addComboBox_selectsMatchingValue() {
    EnumerableOptionCallback callback = org.mockito.Mockito.mock(EnumerableOptionCallback.class);
    when(callback.getPossibleValues()).thenReturn(new String[] {"one", "two"});

    HTMLNode combo = ConfigToadlet.addComboBox("two", callback, "full.name", false);

    assertEquals("select", combo.getName());
    assertEquals("full.name", combo.getAttribute("name"));

    List<HTMLNode> options = combo.getChildren();
    assertEquals(2, options.size());
    assertNull(options.get(0).getAttribute("selected"));
    assertEquals("selected", options.get(1).getAttribute("selected"));
    assertEquals("two", options.get(1).getAttribute("value"));
  }

  @Test
  void addComboBox_whenDisabled_setsDisabledOnSelect() {
    EnumerableOptionCallback callback = org.mockito.Mockito.mock(EnumerableOptionCallback.class);
    when(callback.getPossibleValues()).thenReturn(new String[] {"alpha"});

    HTMLNode combo = ConfigToadlet.addComboBox("alpha", callback, "name", true);

    assertEquals("disabled", combo.getAttribute("disabled"));
  }

  @Test
  void addBooleanComboBox_whenTrue_marksTrueSelected() {
    HTMLNode combo = ConfigToadlet.addBooleanComboBox(true, "bool.option", false);

    List<HTMLNode> children = combo.getChildren();
    assertEquals(2, children.size());
    assertEquals("selected", children.get(0).getAttribute("selected"));
    assertNull(children.get(1).getAttribute("selected"));
  }

  @Test
  void addBooleanComboBox_whenFalse_marksFalseSelected() {
    HTMLNode combo = ConfigToadlet.addBooleanComboBox(false, "bool.option", false);

    List<HTMLNode> children = combo.getChildren();
    assertEquals(2, children.size());
    assertNull(children.get(0).getAttribute("selected"));
    assertEquals("selected", children.get(1).getAttribute("selected"));
  }

  @Test
  void addBooleanComboBox_whenDisabled_setsDisabledOnSelect() {
    HTMLNode combo = ConfigToadlet.addBooleanComboBox(true, "bool.option", true);

    assertEquals("disabled", combo.getAttribute("disabled"));
  }

  @Test
  void path_returnsPrefixFromSubConfig() {
    when(subConfig.getPrefix()).thenReturn("fproxy");

    ConfigToadlet toadlet = createToadlet();

    assertEquals("/config/fproxy", toadlet.path());
  }

  @Test
  void isEnabled_returnsTrueWhenAdvancedModeEnabled() {
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {});

    ConfigToadlet toadlet = createToadlet();

    assertTrue(toadlet.isEnabled(ctx));
  }

  @Test
  void isEnabled_returnsTrueWhenNonExpertOptionPresent() {
    Option<?> expertOption = org.mockito.Mockito.mock(Option.class);
    when(expertOption.isExpert()).thenReturn(true);
    Option<?> normalOption = org.mockito.Mockito.mock(Option.class);
    when(normalOption.isExpert()).thenReturn(false);

    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {expertOption, normalOption});

    ConfigToadlet toadlet = createToadlet();

    assertTrue(toadlet.isEnabled(ctx));
  }

  @Test
  void isEnabled_returnsFalseWhenAllOptionsExpertAndAdvancedDisabled() {
    Option<?> expertOption1 = org.mockito.Mockito.mock(Option.class);
    Option<?> expertOption2 = org.mockito.Mockito.mock(Option.class);
    when(expertOption1.isExpert()).thenReturn(true);
    when(expertOption2.isExpert()).thenReturn(true);

    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {expertOption1, expertOption2});

    ConfigToadlet toadlet = createToadlet();

    assertFalse(toadlet.isEnabled(ctx));
  }

  @Test
  void handleMethodPOST_whenConfirmResetRequested_rendersConfirmationPageWithMatchingParts()
      throws Exception {
    when(subConfig.getPrefix()).thenReturn("node");
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    stubPageMaker();
    stubInfoboxCreation();
    stubFormChildCreation();

    HTTPRequest request =
        createRequest(
            Map.ofEntries(
                Map.entry("confirm-reset-to-defaults", "true"),
                Map.entry("subconfig", "node"),
                Map.entry("node.option", "value"),
                Map.entry("other.option", "ignored")));

    ConfigToadlet toadlet = createToadlet();

    toadlet.handleMethodPOST(CONFIG_URI, request, ctx);

    String body = captureWrittenBody();

    assertTrue(body.contains("name=\"subconfig\""));
    assertTrue(body.contains("value=\"node\""));
    assertTrue(body.contains("name=\"node.option\""));
    assertTrue(body.contains("value=\"value\""));
    assertFalse(body.contains("name=\"other.option\""));
    assertTrue(body.contains("name=\"reset-to-defaults\""));
    assertTrue(body.contains("name=\"decline-default-reset\""));
  }

  @Test
  void handleMethodPOST_whenDirectorySelectorRequested_redirectsUsingDownloadsDir()
      throws Exception {
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);

    File downloadsDir = new File("build/test-downloads").getAbsoluteFile();
    when(transferAccessPort.downloadsDir()).thenReturn(downloadsDir);

    LinkedHashMap<String, String> parts = new LinkedHashMap<>();
    parts.put("subconfig", "node");
    parts.put("node.other", "with spaces");
    parts.put("select-directory.node.downloadsDir", "browse");

    ConfigToadlet toadlet =
        new ConfigToadlet(
            "directory-browser",
            config,
            subConfig,
            new ConfigToadletRuntimePorts(configPort, transferAccessPort, lifecyclePort));

    toadlet.handleMethodPOST(CONFIG_URI, createRequest(parts), ctx);

    assertEquals(
        "/directory-browser/?subconfig=node&node.other=with%20spaces&select-for=node.downloadsDir&path="
            + downloadsDir.getAbsolutePath(),
        captureRedirectLocation());
    verify(configPort, never()).persist();
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void handleMethodPOST_whenOptionChanges_persistsConfigAndAppliesValue() throws Exception {
    when(subConfig.getPrefix()).thenReturn("node");
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {});
    when(config.get("node")).thenReturn(subConfig);
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    stubPageMaker();
    stubInfoboxCreation();

    Option<?> option = mock(Option.class);
    when(option.getName()).thenReturn("downloadsDir");
    when(option.getValueDisplayString()).thenReturn("/old");
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {option});

    HTTPRequest request =
        createRequest(
            Map.ofEntries(
                Map.entry("subconfig", "node"), Map.entry("node.downloadsDir", "/new/path")));

    ConfigToadlet toadlet = createToadlet();

    toadlet.handleMethodPOST(CONFIG_URI, request, ctx);

    verify(option).setValue("/new/path");
    verify(configPort).persist();
    assertTrue(captureWrittenBody().contains("href=\"/config/node\""));
  }

  @Test
  void handleMethodPOST_whenRestartRequiredAndWrapperIsUsed_registersAlertAndShowsRestartForm()
      throws Exception {
    when(subConfig.getPrefix()).thenReturn("node");
    when(config.get("node")).thenReturn(subConfig);
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.getFormPassword()).thenReturn("secret");
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(lifecyclePort.isUsingWrapper()).thenReturn(true);
    stubPageMaker();
    stubInfoboxCreation();
    stubFormChildCreation();

    Option<?> option = mock(Option.class);
    when(option.getName()).thenReturn("cacheSize");
    when(option.getValueDisplayString()).thenReturn("old");
    doThrow(new NodeNeedRestartException("restart required")).when(option).setValue("new");
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {option});

    HTTPRequest request =
        createRequest(
            Map.ofEntries(Map.entry("subconfig", "node"), Map.entry("node.cacheSize", "new")));

    ConfigToadlet toadlet = createToadlet();

    toadlet.handleMethodPOST(CONFIG_URI, request, ctx);

    verify(configPort).persist();
    ArgumentCaptor<UserAlert> alertCaptor = ArgumentCaptor.forClass(UserAlert.class);
    verify(alertManager).register(alertCaptor.capture());

    String alertHtml = alertCaptor.getValue().getHTMLText().generate();
    String body = captureWrittenBody();

    assertTrue(alertHtml.contains("name=\"restart2\""));
    assertTrue(alertHtml.contains("value=\"secret\""));
    assertTrue(body.contains("name=\"restart\""));
    assertTrue(body.contains("name=\"restart2\""));
  }

  @Test
  void handleMethodPOST_whenResettingFproxyPortToDefaults_keepsCurrentPortValue() throws Exception {
    when(subConfig.getPrefix()).thenReturn("fproxy");
    when(config.get("fproxy")).thenReturn(subConfig);
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    stubPageMaker();
    stubInfoboxCreation();

    Option<?> option = mock(Option.class);
    when(option.getName()).thenReturn("port");
    when(option.getValueDisplayString()).thenReturn("8888");
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {option});

    HTTPRequest request =
        createRequest(
            Map.ofEntries(
                Map.entry("subconfig", "fproxy"),
                Map.entry("reset-to-defaults", "true"),
                Map.entry("fproxy.port", "ignored")));

    ConfigToadlet toadlet = createToadlet();

    toadlet.handleMethodPOST(CONFIG_URI, request, ctx);

    verify(option, never()).setValue(anyString());
    verify(configPort).persist();
  }

  @Test
  void handleMethodGET_whenWrapperMemorySubmitted_rendersSubmittedPseudoOptionValue()
      throws Exception {
    when(subConfig.getPrefix()).thenReturn("node");
    when(subConfig.getOptions()).thenReturn(new Option<?>[] {});
    when(ctx.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(false);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(new HTMLNode("#", ""));
    stubPageMaker();
    stubFormChildCreation();

    HTTPRequest request = createRequest(Map.ofEntries(Map.entry(WRAPPER_MAX_MEMORY, "768")));

    try (MockedStatic<WrapperConfig> wrapperConfig = mockStatic(WrapperConfig.class)) {
      wrapperConfig.when(WrapperConfig::canChangeProperties).thenReturn(true);
      wrapperConfig
          .when(() -> WrapperConfig.getWrapperProperty(WRAPPER_MAX_MEMORY))
          .thenReturn("512");

      ConfigToadlet toadlet = createToadlet();

      toadlet.handleMethodGET(CONFIG_URI, request, ctx);
    }

    String body = captureWrittenBody();

    assertTrue(body.contains("name=\"" + WRAPPER_MAX_MEMORY + "\""));
    assertTrue(body.contains("value=\"768\""));
  }

  @Test
  @SuppressWarnings("deprecation")
  void resolveOptionType_whenLegacyBooleanCallback_expectBoolean() throws Exception {
    ConfigToadlet toadlet = createToadlet();
    ConfigCallback<?> callback =
        new network.crypta.support.api.BooleanCallback() {
          @Override
          public Boolean get() {
            return true;
          }

          @Override
          public void set(Boolean value) {
            ignoreCallbackMutation();
          }
        };
    Object optionType = resolveOptionType(toadlet, callback);

    assertEquals("BOOLEAN", optionType.toString());
  }

  @Test
  void resolveOptionType_whenWritableProgramDirectoryCallback_expectDirectory() throws Exception {
    ConfigToadlet toadlet = createToadlet();
    ConfigCallback<?> callback = new ProgramDirectory("move.error").getStringCallback();

    Object optionType = resolveOptionType(toadlet, callback);

    assertEquals("DIRECTORY", optionType.toString());
  }

  @Test
  void resolveOptionType_whenReadOnlyProgramDirectoryCallback_expectTextReadOnly()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    ConfigCallback<?> callback = new ProgramDirectory().getStringCallback();

    Object optionType = resolveOptionType(toadlet, callback);

    assertEquals("TEXT_READ_ONLY", optionType.toString());
  }

  @Test
  void resolveOptionType_whenMarkerBasedWritableDirectoryCallback_expectDirectory()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    ConfigCallback<?> callback = new MarkerDirectoryStringCallback(false);

    Object optionType = resolveOptionType(toadlet, callback);

    assertEquals("DIRECTORY", optionType.toString());
  }

  @Test
  void resolveOptionType_whenMarkerBasedReadOnlyDirectoryCallback_expectTextReadOnly()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    ConfigCallback<?> callback = new MarkerDirectoryStringCallback(true);

    Object optionType = resolveOptionType(toadlet, callback);

    assertEquals("TEXT_READ_ONLY", optionType.toString());
  }

  @Test
  @SuppressWarnings("deprecation")
  void resolveOptionType_whenLegacyEnumerableStringCallbackRegistered_expectDropDown()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    Config compatConfig = new Config();
    SubConfig compatSubConfig = compatConfig.createSubConfig("compat");
    network.crypta.support.api.StringCallback callback =
        new LegacyEnumerableStringCallback("dark", new String[] {"light", "dark"});
    StringOption option =
        new StringOption(
            compatSubConfig,
            "theme",
            "dark",
            new Option.Meta(1, false, false, "sd", "ld"),
            callback);

    Object optionType = resolveOptionType(toadlet, option.getCallback());

    assertEquals("DROP_DOWN", optionType.toString());
  }

  @Test
  @SuppressWarnings("deprecation")
  void resolveOptionType_whenLegacyEnumerableMarkerDirectoryCallbackRegistered_expectDropDown()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    Config compatConfig = new Config();
    SubConfig compatSubConfig = compatConfig.createSubConfig("compat");
    network.crypta.support.api.StringCallback callback =
        new LegacyEnumerableDirectoryStringCallback("dark", false, new String[] {"light", "dark"});
    StringOption option =
        new StringOption(
            compatSubConfig,
            "theme",
            "dark",
            new Option.Meta(1, false, false, "sd", "ld"),
            callback);

    Object optionType = resolveOptionType(toadlet, option.getCallback());

    assertEquals("DROP_DOWN", optionType.toString());
  }

  @Test
  @SuppressWarnings("deprecation")
  void resolveOptionType_whenLegacyMarkerDirectoryCallbackConstructed_expectDirectory()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    Config compatConfig = new Config();
    SubConfig compatSubConfig = compatConfig.createSubConfig("compat");
    network.crypta.support.api.StringCallback callback =
        new LegacyDirectoryStringCallback("directory", false);
    StringOption option =
        new StringOption(
            compatSubConfig, "dir", "path", new Option.Meta(1, false, false, "sd", "ld"), callback);

    Object optionType = resolveOptionType(toadlet, option.getCallback());

    assertEquals("DIRECTORY", optionType.toString());
  }

  @Test
  @SuppressWarnings("deprecation")
  void resolveOptionType_whenLegacyMarkerDirectoryCallbackRegisteredReadOnly_expectTextReadOnly()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    Config compatConfig = new Config();
    SubConfig compatSubConfig = compatConfig.createSubConfig("compat");

    compatSubConfig.register(
        "dir",
        "path",
        new Option.Meta(1, false, false, "sd", "ld"),
        new LegacyDirectoryStringCallback("directory", true));

    Object optionType = resolveOptionType(toadlet, compatSubConfig.getOption("dir").getCallback());

    assertEquals("TEXT_READ_ONLY", optionType.toString());
  }

  @Test
  @SuppressWarnings("deprecation")
  void resolveOptionType_whenLegacyProgramDirectoryCallbackRegistered_expectDirectory()
      throws Exception {
    ConfigToadlet toadlet = createToadlet();
    Config compatConfig = new Config();
    SubConfig compatSubConfig = compatConfig.createSubConfig("compat");
    network.crypta.support.api.StringCallback callback =
        new ProgramDirectory("move.error").getStringCallback();
    StringOption option =
        new StringOption(
            compatSubConfig, "dir", "path", new Option.Meta(1, false, false, "sd", "ld"), callback);

    Object optionType = resolveOptionType(toadlet, option.getCallback());

    assertEquals("DIRECTORY", optionType.toString());
  }

  private Object resolveOptionType(ConfigToadlet toadlet, ConfigCallback<?> callback)
      throws Exception {
    Method resolveOptionType =
        ConfigToadlet.class.getDeclaredMethod("resolveOptionType", ConfigCallback.class);
    resolveOptionType.setAccessible(true);
    return resolveOptionType.invoke(toadlet, callback);
  }

  private static final class MarkerDirectoryStringCallback extends StringCallback
      implements DirectorySelectionCallback {
    private final boolean readOnly;

    private MarkerDirectoryStringCallback(boolean readOnly) {
      this.readOnly = readOnly;
    }

    @Override
    public String get() {
      return "directory";
    }

    @Override
    public void set(String value) {
      ignoreCallbackMutation();
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }
  }

  @SuppressWarnings("deprecation")
  private static final class LegacyDirectoryStringCallback
      extends network.crypta.support.api.StringCallback implements DirectorySelectionCallback {
    private final String value;
    private final boolean readOnly;

    private LegacyDirectoryStringCallback(String value, boolean readOnly) {
      this.value = value;
      this.readOnly = readOnly;
    }

    @Override
    public String get() {
      return value;
    }

    @Override
    public void set(String updatedValue) {
      ignoreCallbackMutation();
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }
  }

  @SuppressWarnings("deprecation")
  private static final class LegacyEnumerableDirectoryStringCallback
      extends network.crypta.support.api.StringCallback
      implements EnumerableOptionCallback, DirectorySelectionCallback {
    private final String currentValue;
    private final boolean readOnly;
    private final String[] possibleValues;

    private LegacyEnumerableDirectoryStringCallback(
        String currentValue, boolean readOnly, String[] possibleValues) {
      this.currentValue = currentValue;
      this.readOnly = readOnly;
      this.possibleValues = possibleValues;
    }

    @Override
    public String get() {
      return currentValue;
    }

    @Override
    public void set(String value) {
      ignoreCallbackMutation();
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }

    @Override
    public String[] getPossibleValues() {
      return possibleValues;
    }
  }

  @SuppressWarnings("deprecation")
  private static final class LegacyEnumerableStringCallback
      extends network.crypta.support.api.StringCallback implements EnumerableOptionCallback {
    private final String currentValue;
    private final String[] possibleValues;

    private LegacyEnumerableStringCallback(String currentValue, String[] possibleValues) {
      this.currentValue = currentValue;
      this.possibleValues = possibleValues;
    }

    @Override
    public String get() {
      return currentValue;
    }

    @Override
    public void set(String value) {
      ignoreCallbackMutation();
    }

    @Override
    public String[] getPossibleValues() {
      return possibleValues;
    }
  }

  private HTTPRequest createRequest(Map<String, String> parts) {
    HTTPRequest request = mock(HTTPRequest.class);
    lenient().when(request.getParts()).thenReturn(parts.keySet().toArray(String[]::new));
    when(request.isPartSet(anyString()))
        .thenAnswer(invocation -> parts.containsKey(invocation.getArgument(0, String.class)));
    when(request.getPartAsStringFailsafe(anyString(), anyInt()))
        .thenAnswer(invocation -> parts.getOrDefault(invocation.getArgument(0, String.class), ""));
    return request;
  }

  private static void ignoreCallbackMutation() {
    // These helper callbacks exist only to exercise ConfigToadlet option-type resolution.
  }

  private void stubPageMaker() {
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(anyString(), eq(ctx))).thenAnswer(_ -> createPageNode());
  }

  private void stubInfoboxCreation() {
    when(pageMaker.getInfobox(
            anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean()))
        .thenAnswer(
            invocation ->
                createInfoboxContent(
                    invocation.getArgument(0),
                    invocation.getArgument(1),
                    invocation.getArgument(2),
                    invocation.getArgument(3),
                    invocation.getArgument(4)));
  }

  private void stubFormChildCreation() {
    when(ctx.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation ->
                createFormNode(
                    invocation.getArgument(0),
                    invocation.getArgument(1),
                    invocation.getArgument(2)));
  }

  private static PageNode createPageNode() {
    HTMLNode outer = new HTMLNode("html");
    HTMLNode head = outer.addChild("head");
    HTMLNode body = outer.addChild("body");
    HTMLNode content = body.addChild("div", "id", "content");
    return new PageNode(outer, head, content);
  }

  private static HTMLNode createInfoboxContent(
      String category, String header, HTMLNode parent, String title, boolean isUnique) {
    String cssClass = (category == null) ? "infobox" : "infobox " + category;
    HTMLNode infobox = new HTMLNode("div", "class", cssClass);
    if (isUnique && title != null) {
      infobox.addAttribute("id", title);
    }
    infobox.addChild("div", "class", "infobox-header").addChild("#", header);
    HTMLNode contentNode = infobox.addChild("div", "class", "infobox-content");
    parent.addChild(infobox);
    return contentNode;
  }

  private static HTMLNode createFormNode(HTMLNode parent, String target, String id) {
    HTMLNode form =
        new HTMLNode(
            "form",
            new String[] {"action", "method", "enctype", "id", "name"},
            new String[] {target, "post", "multipart/form-data", id, id});
    parent.addChild(form);
    return form;
  }

  private String captureWrittenBody() throws Exception {
    ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
    ArgumentCaptor<Integer> offsetCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> lengthCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(ctx).writeData(dataCaptor.capture(), offsetCaptor.capture(), lengthCaptor.capture());
    return new String(
        dataCaptor.getValue(),
        offsetCaptor.getValue(),
        lengthCaptor.getValue(),
        StandardCharsets.UTF_8);
  }

  @SuppressWarnings("unchecked")
  private String captureRedirectLocation() throws Exception {
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    return headersCaptor.getValue().getFirst("Location");
  }
}
