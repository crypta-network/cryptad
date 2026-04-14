package network.crypta.clients.http.wizardsteps;

import java.util.List;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DatastoreSizeTest {

  private static final String ATTR_NAME = "name";
  private static final String ATTR_SELECTED = "selected";
  private static final String ATTR_VALUE = "value";
  private static final String KEY_CLIENT_CACHE_SIZE = "clientCacheSize";
  private static final String KEY_CLIENT_CACHE_TYPE = "clientCacheType";
  private static final String KEY_INPUT_BANDWIDTH_LIMIT = "inputBandwidthLimit";
  private static final String KEY_OUTPUT_BANDWIDTH_LIMIT = "outputBandwidthLimit";
  private static final String KEY_SLASHDOT_CACHE_LIFETIME = "slashdotCacheLifetime";
  private static final String KEY_SLASHDOT_CACHE_SIZE = "slashdotCacheSize";
  private static final String KEY_STORE_SIZE = "storeSize";
  private static final String KEY_STORE_TYPE = "storeType";
  private static final long MAX_STORAGE_LIMIT_BYTES = 5L * 1024 * 1024 * 1024;
  private static final String TAG_OPTION = "option";
  private static final String TAG_SELECT = "select";
  private static final String VALUE_DEFAULT = "default";
  private static final String VALUE_SALT_HASH = "salt-hash";

  @Test
  void setDatastoreSize_whenUnparseable_expectNumberFormatException() {
    Config config = newConfigWithNodeDefaults(10, 10, 1000L);
    assertThrows(
        NumberFormatException.class,
        () -> DatastoreSize.setDatastoreSize("not-a-number", config, () -> Long.MAX_VALUE));
  }

  @Test
  void setDatastoreSize_whenSelectedSizeExceedsMax_expectNoChanges() {
    Config config = newConfigWithNodeDefaults(10, 10, 1000L);
    SubConfig node = config.get("node");
    assertNotNull(node);

    long defaultStoreSize = Config.longOption(node, KEY_STORE_SIZE).getValue();
    long defaultClientCacheSize = Config.longOption(node, KEY_CLIENT_CACHE_SIZE).getValue();
    long defaultSlashdotCacheSize = Config.longOption(node, KEY_SLASHDOT_CACHE_SIZE).getValue();
    String defaultStoreType = node.getString(KEY_STORE_TYPE);
    String defaultClientCacheType = node.getString(KEY_CLIENT_CACHE_TYPE);

    DatastoreSize.setDatastoreSize("2KiB", config, () -> 1024L);

    assertEquals(defaultStoreSize, Config.longOption(node, KEY_STORE_SIZE).getValue());
    assertEquals(defaultClientCacheSize, Config.longOption(node, KEY_CLIENT_CACHE_SIZE).getValue());
    assertEquals(
        defaultSlashdotCacheSize, Config.longOption(node, KEY_SLASHDOT_CACHE_SIZE).getValue());
    assertEquals(defaultStoreType, node.getString(KEY_STORE_TYPE));
    assertEquals(defaultClientCacheType, node.getString(KEY_CLIENT_CACHE_TYPE));
  }

  @Test
  void setDatastoreSize_whenValidAndFirstTime_expectConfigSizesAndTypesSet() {
    Config config = newConfigWithNodeDefaults(10, 0, 1000L);
    SubConfig node = config.get("node");
    assertNotNull(node);

    long selectedSize = Fields.parseLong("1GiB");

    DatastoreSize.setDatastoreSize("1GiB", config, () -> selectedSize + 1);

    long expectedClientCacheSize = selectedSize / 10;
    long expectedSlashdotCacheSize = 10L;
    long expectedStoreSize = selectedSize - (expectedClientCacheSize + expectedSlashdotCacheSize);

    assertEquals(expectedStoreSize, Config.longOption(node, KEY_STORE_SIZE).getValue());
    assertEquals(
        expectedClientCacheSize, Config.longOption(node, KEY_CLIENT_CACHE_SIZE).getValue());
    assertEquals(
        expectedSlashdotCacheSize, Config.longOption(node, KEY_SLASHDOT_CACHE_SIZE).getValue());
    assertEquals(VALUE_SALT_HASH, node.getString(KEY_STORE_TYPE));
    assertEquals(VALUE_SALT_HASH, node.getString(KEY_CLIENT_CACHE_TYPE));
  }

  @Test
  void postStep_whenFirstTime_expectNextStepBandwidthAndUsesSelected() {
    Config config = newConfigWithNodeDefaults(10, 0, 1000L);
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(snapshot(2L * 1024 * 1024 * 1024));
    DatastoreSize step = new DatastoreSize(wizardPort, config);

    HTTPRequest request = mock(HTTPRequest.class);
    when(request.isPartSet("singlestep")).thenReturn(false);
    when(request.getPartAsStringFailsafe("ds", 20)).thenReturn("1GiB");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.BANDWIDTH.name(), next);

    SubConfig node = config.get("node");
    assertNotNull(node);
    assertEquals(VALUE_SALT_HASH, node.getString(KEY_STORE_TYPE));
    assertEquals(VALUE_SALT_HASH, node.getString(KEY_CLIENT_CACHE_TYPE));
  }

  @Test
  void postStep_whenSingleStep_expectNextStepCompleteAndDoesNotSetTypes() {
    Config config = newConfigWithNodeDefaults(10, 0, 1000L);
    SubConfig node = config.get("node");
    assertNotNull(node);
    assertEquals(VALUE_DEFAULT, node.getString(KEY_STORE_TYPE));
    assertEquals(VALUE_DEFAULT, node.getString(KEY_CLIENT_CACHE_TYPE));

    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(snapshot(2L * 1024 * 1024 * 1024));
    DatastoreSize step = new DatastoreSize(wizardPort, config);

    HTTPRequest request = mock(HTTPRequest.class);
    when(request.isPartSet("singlestep")).thenReturn(true);
    when(request.getPartAsStringFailsafe("ds", 20)).thenReturn("1GiB");

    String next = step.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.COMPLETE.name(), next);

    assertEquals(VALUE_DEFAULT, node.getString(KEY_STORE_TYPE));
    assertEquals(VALUE_DEFAULT, node.getString(KEY_CLIENT_CACHE_TYPE));
    assertTrue(Config.longOption(node, KEY_STORE_SIZE).getValue() > 0);
  }

  @ParameterizedTest
  @CsvSource({"10GiB, 1073741824, 209715200", "1GiB, 107374182, 107374182"})
  void setDatastoreSize_whenDifferentSizes_expectClientCacheMatchesExpectation(
      String selected, long expectedSizeDivTen, long expectedClientCacheSize) {
    Config config = newConfigWithNodeDefaults(1_000_000_000, 1_000_000_000, 1_000_000_000L);
    SubConfig node = config.get("node");
    assertNotNull(node);

    long selectedSize = Fields.parseLong(selected);
    DatastoreSize.setDatastoreSize(selected, config, () -> selectedSize + 1);

    long actualClientCacheSize = Config.longOption(node, KEY_CLIENT_CACHE_SIZE).getValue();
    assertEquals(expectedClientCacheSize, actualClientCacheSize);

    long actualSlashdotCacheSize = Config.longOption(node, KEY_SLASHDOT_CACHE_SIZE).getValue();
    assertEquals(expectedSizeDivTen, actualSlashdotCacheSize);
  }

  @Test
  void getStep_whenAutodetectedIs512MiB_expectNo512MOption() {
    Config config = newConfigWithNodeDefaults(10, 10, 1000L);
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(snapshot(512L * 1024 * 1024));

    DatastoreSize step = new DatastoreSize(wizardPort, config);

    PageHelper helper = mock(PageHelper.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    when(helper.getInfobox(anyString(), anyString(), eq(contentNode), any(), anyBoolean()))
        .thenReturn(infoboxNode);
    when(helper.addFormChild(eq(infoboxNode), anyString(), anyString())).thenReturn(formNode);

    step.getStep(mock(HTTPRequest.class), helper);

    HTMLNode selectNode = findDatastoreSelect(formNode);
    assertNo512MOption(selectNode);
    assertOptionValuePresent(selectNode, "1G");
  }

  @Test
  void getStep_whenAutodetectedIsNot512MiB_expect512MOptionPresent() {
    Config config = newConfigWithNodeDefaults(10, 10, 1000L);
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(snapshot(2L * 1024 * 1024 * 1024));

    DatastoreSize step = new DatastoreSize(wizardPort, config);

    PageHelper helper = mock(PageHelper.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    when(helper.getInfobox(anyString(), anyString(), eq(contentNode), any(), anyBoolean()))
        .thenReturn(infoboxNode);
    when(helper.addFormChild(eq(infoboxNode), anyString(), anyString())).thenReturn(formNode);

    step.getStep(mock(HTTPRequest.class), helper);

    HTMLNode selectNode = findDatastoreSelect(formNode);
    assertOptionValuePresent(selectNode, "512M");
    assertOptionValuePresent(selectNode, "1G");
  }

  @Test
  void getStep_whenCurrentSettingsNonDefault_expectCurrentOptionSelected() throws Exception {
    Config config = newConfigWithNodeDefaults(10, 10, 1000L);
    SubConfig nodeConfig = config.get("node");
    assertNotNull(nodeConfig);
    nodeConfig.set(KEY_STORE_SIZE, "1GiB");
    nodeConfig.set(KEY_CLIENT_CACHE_SIZE, "512MiB");
    nodeConfig.set(KEY_SLASHDOT_CACHE_SIZE, "256MiB");

    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(snapshot(-1L));

    DatastoreSize step = new DatastoreSize(wizardPort, config);

    PageHelper helper = mock(PageHelper.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    when(helper.getInfobox(anyString(), anyString(), eq(contentNode), any(), anyBoolean()))
        .thenReturn(infoboxNode);
    when(helper.addFormChild(eq(infoboxNode), anyString(), anyString())).thenReturn(formNode);

    long expectedTotal =
        Config.longOption(nodeConfig, KEY_STORE_SIZE).getValue()
            + Config.longOption(nodeConfig, KEY_CLIENT_CACHE_SIZE).getValue()
            + Config.longOption(nodeConfig, KEY_SLASHDOT_CACHE_SIZE).getValue();
    String expectedValue = SizeUtil.formatSize(expectedTotal);

    step.getStep(mock(HTTPRequest.class), helper);

    HTMLNode selectNode = findDatastoreSelect(formNode);
    HTMLNode selectedOption =
        selectNode.getChildren().stream()
            .filter(child -> TAG_OPTION.equals(child.getName()))
            .filter(child -> "on".equals(child.getAttribute(ATTR_SELECTED)))
            .findFirst()
            .orElseThrow();

    assertEquals(expectedValue, selectedOption.getAttribute(ATTR_VALUE));
    assertTrue(selectedOption.generateChildren().contains(expectedValue));
    assertTrue(selectedOption.generateChildren().contains(WizardL10n.l10n("currentPrefix")));
  }

  @Test
  void getStep_whenLegacyCapIsBelowSnapshotMax_expectLegacyThresholdsPreserved() {
    Config config = newConfigWithNodeDefaults(10, 10, 1000L);
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(snapshot(4L * 1024 * 1024 * 1024, -1L));

    DatastoreSize step = new DatastoreSize(wizardPort, config);

    PageHelper helper = mock(PageHelper.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    when(helper.getInfobox(anyString(), anyString(), eq(contentNode), any(), anyBoolean()))
        .thenReturn(infoboxNode);
    when(helper.addFormChild(eq(infoboxNode), anyString(), anyString())).thenReturn(formNode);

    step.getStep(mock(HTTPRequest.class), helper);

    HTMLNode selectNode = findDatastoreSelect(formNode);
    assertOptionValuePresent(selectNode, "3G");
    assertOptionValueAbsent(selectNode, "5G");
  }

  @Test
  void getStep_whenLegacyCapIsAboveSnapshotMax_expectLegacyThresholdsPreserved() {
    Config config = newConfigWithNodeDefaults(10, 10, 1000L);
    FirstTimeWizardPort wizardPort = mock(FirstTimeWizardPort.class);
    when(wizardPort.snapshot()).thenReturn(snapshot(50L * 1024 * 1024 * 1024, -1L));

    DatastoreSize step = new DatastoreSize(wizardPort, config);

    PageHelper helper = mock(PageHelper.class);
    HTMLNode contentNode = new HTMLNode("div");
    HTMLNode infoboxNode = new HTMLNode("div");
    HTMLNode formNode = new HTMLNode("form");
    when(helper.getPageContent(anyString())).thenReturn(contentNode);
    when(helper.getInfobox(anyString(), anyString(), eq(contentNode), any(), anyBoolean()))
        .thenReturn(infoboxNode);
    when(helper.addFormChild(eq(infoboxNode), anyString(), anyString())).thenReturn(formNode);

    step.getStep(mock(HTTPRequest.class), helper);

    HTMLNode selectNode = findDatastoreSelect(formNode);
    assertOptionValuePresent(selectNode, "20G");
    assertOptionValuePresent(selectNode, "50G");
    assertOptionValueAbsent(selectNode, "200G");
  }

  private static Config newConfigWithNodeDefaults(
      int upstreamLimit, int downstreamLimit, long slashdotLifetimeMs) {
    Config config = new Config();
    SubConfig node = config.createSubConfig("node");

    node.register(
        KEY_OUTPUT_BANDWIDTH_LIMIT,
        upstreamLimit,
        new Option.Meta(0, false, false, "", ""),
        (network.crypta.config.IntCallback) null,
        false);
    node.register(
        KEY_INPUT_BANDWIDTH_LIMIT,
        downstreamLimit,
        new Option.Meta(0, false, false, "", ""),
        (network.crypta.config.IntCallback) null,
        false);
    node.register(
        KEY_SLASHDOT_CACHE_LIFETIME,
        slashdotLifetimeMs,
        new Option.Meta(0, false, false, "", ""),
        null,
        false);

    node.register(KEY_STORE_SIZE, 0L, new Option.Meta(0, false, false, "", ""), null, true);
    node.register(KEY_CLIENT_CACHE_SIZE, 0L, new Option.Meta(0, false, false, "", ""), null, true);
    node.register(
        KEY_SLASHDOT_CACHE_SIZE, 0L, new Option.Meta(0, false, false, "", ""), null, true);

    node.register(
        KEY_STORE_TYPE,
        VALUE_DEFAULT,
        new Option.Meta(0, false, false, "", ""),
        (network.crypta.config.StringCallback) null);
    node.register(
        KEY_CLIENT_CACHE_TYPE,
        VALUE_DEFAULT,
        new Option.Meta(0, false, false, "", ""),
        (network.crypta.config.StringCallback) null);

    return config;
  }

  private static FirstTimeWizardSnapshot snapshot(long autodetectedSize) {
    return snapshot(MAX_STORAGE_LIMIT_BYTES, autodetectedSize);
  }

  private static FirstTimeWizardSnapshot snapshot(
      long legacyMaxStorageLimitBytes, long autodetectedSize) {
    return new FirstTimeWizardSnapshot(
        false,
        "2.00",
        "1.25",
        1L,
        SizeUtil.formatSize(MAX_STORAGE_LIMIT_BYTES),
        MAX_STORAGE_LIMIT_BYTES,
        legacyMaxStorageLimitBytes,
        10L,
        976562L,
        "49.44",
        "",
        "",
        null,
        autodetectedSize);
  }

  private static HTMLNode findDatastoreSelect(HTMLNode formNode) {
    List<HTMLNode> selects =
        formNode.getChildren().stream()
            .filter(child -> TAG_SELECT.equals(child.getName()))
            .filter(child -> "ds".equals(child.getAttribute(ATTR_NAME)))
            .toList();
    assertEquals(1, selects.size());
    return selects.getFirst();
  }

  private static void assertOptionValuePresent(HTMLNode selectNode, String expectedValue) {
    assertTrue(
        selectNode.getChildren().stream()
            .filter(child -> TAG_OPTION.equals(child.getName()))
            .anyMatch(child -> expectedValue.equals(child.getAttribute(ATTR_VALUE))),
        "Expected an <option> with value '" + expectedValue + "'");
  }

  private static void assertNo512MOption(HTMLNode selectNode) {
    assertOptionValueAbsent(selectNode, "512M");
  }

  private static void assertOptionValueAbsent(HTMLNode selectNode, String forbiddenValue) {
    assertTrue(
        selectNode.getChildren().stream()
            .filter(child -> TAG_OPTION.equals(child.getName()))
            .noneMatch(child -> forbiddenValue.equals(child.getAttribute(ATTR_VALUE))),
        "Did not expect an <option> with value '" + forbiddenValue + "'");
  }
}
