package network.crypta.clients.http;

import java.util.List;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.Config;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;

import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ConfigToadletTest {

  @Mock private SubConfig subConfig;
  @Mock private Config config;
  @Mock private HighLevelSimpleClient client;
  @Mock private ConfigPort configPort;
  @Mock private TransferAccessPort transferAccessPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private ToadletContext ctx;

  private ConfigToadlet createToadlet() {
    return new ConfigToadlet(
        client,
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
}
