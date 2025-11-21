package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.StringOption;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.StringCallback;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ModifyConfigTest {

  @Mock FCPConnectionHandler handler;

  @Mock Node node;

  @Mock NodeClientCore clientCore;

  @Test
  void constructor_whenIdentifierPresent_storesItAndRemovesFromFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "id-42");

    ModifyConfig modifyConfig = new ModifyConfig(fs);

    assertEquals("id-42", modifyConfig.requestIdentifier);
    assertNull(fs.get("Identifier"));
  }

  @Test
  void getFieldSet_whenCalled_returnsEmptySimpleFieldSet() {
    ModifyConfig modifyConfig = new ModifyConfig(new SimpleFieldSet(true));

    SimpleFieldSet result = modifyConfig.getFieldSet();

    assertNotNull(result);
    assertTrue(result.isEmpty());
  }

  @Test
  void getName_whenCalled_returnsConstantName() {
    ModifyConfig modifyConfig = new ModifyConfig(new SimpleFieldSet(true));

    assertEquals("ModifyConfig", modifyConfig.getName());
  }

  @Test
  void run_whenHandlerLacksFullAccess_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "blocked-id");
    ModifyConfig modifyConfig = new ModifyConfig(fs);
    when(handler.hasFullAccess()).thenReturn(false);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> modifyConfig.run(handler, node));

    assertEquals(ProtocolErrorMessage.ACCESS_DENIED, thrown.protocolCode);
    assertEquals("blocked-id", thrown.ident);
    assertEquals("ModifyConfig requires full access", thrown.getMessage());
    assertFalse(thrown.global);
    verify(handler, never()).send(any(FCPMessage.class));
  }

  @Test
  void run_whenValueDiffers_updatesOptionStoresConfigAndSendsReply() throws Exception {
    PersistentConfig config = new PersistentConfig(null);
    SubConfig subConfig = config.createSubConfig("node");
    CountingStringCallback callback = new CountingStringCallback("5");
    StringOption option =
        new StringOption(subConfig, "maxPeers", "5", 0, false, false, null, null, callback);
    subConfig.register(option);
    when(node.getConfig()).thenReturn(config);
    when(node.getClientCore()).thenReturn(clientCore);
    when(handler.hasFullAccess()).thenReturn(true);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "cfg-1");
    fs.putSingle("node.maxPeers", "10");
    ModifyConfig modifyConfig = new ModifyConfig(fs);

    modifyConfig.run(handler, node);

    assertEquals(1, callback.getSetCount());
    assertEquals("10", option.getValueString());
    assertEquals("10", callback.getCurrentValue());
    InOrder order = inOrder(clientCore, handler);
    order.verify(clientCore).storeConfig();
    ArgumentCaptor<ConfigData> captor = ArgumentCaptor.forClass(ConfigData.class);
    order.verify(handler).send(captor.capture());
    ConfigData sent = captor.getValue();
    assertEquals(node, sent.node);
    assertEquals("cfg-1", sent.requestIdentifier);
  }

  @Test
  void run_whenValueUnchanged_doesNotInvokeSetValueButStillStoresAndSends() throws Exception {
    PersistentConfig config = new PersistentConfig(null);
    SubConfig subConfig = config.createSubConfig("ui");
    CountingStringCallback callback = new CountingStringCallback("light");
    StringOption option =
        new StringOption(subConfig, "theme", "light", 0, false, false, null, null, callback);
    subConfig.register(option);
    when(node.getConfig()).thenReturn(config);
    when(node.getClientCore()).thenReturn(clientCore);
    when(handler.hasFullAccess()).thenReturn(true);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "cfg-2");
    fs.putSingle("ui.theme", "light");
    ModifyConfig modifyConfig = new ModifyConfig(fs);

    modifyConfig.run(handler, node);

    assertEquals(0, callback.getSetCount());
    assertEquals("light", option.getValueString());
    verify(clientCore).storeConfig();
    verify(handler).send(any(ConfigData.class));
  }

  @Test
  void run_whenOptionUpdateFails_continuesToStoreAndRespond() throws Exception {
    PersistentConfig config = new PersistentConfig(null);
    SubConfig subConfig = config.createSubConfig("net");
    ThrowingStringCallback callback = new ThrowingStringCallback("8080");
    StringOption failingOption =
        new StringOption(subConfig, "port", "8080", 0, false, false, null, null, callback);
    subConfig.register(failingOption);
    when(node.getConfig()).thenReturn(config);
    when(node.getClientCore()).thenReturn(clientCore);
    when(handler.hasFullAccess()).thenReturn(true);
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", "cfg-3");
    fs.putSingle("net.port", "9090");
    ModifyConfig modifyConfig = new ModifyConfig(fs);

    modifyConfig.run(handler, node);

    assertEquals("8080", failingOption.getValueString());
    verify(clientCore).storeConfig();
    verify(handler).send(any(ConfigData.class));
  }

  private static final class CountingStringCallback extends StringCallback {
    private int setCount;
    private String currentValue;

    CountingStringCallback(String initialValue) {
      this.currentValue = initialValue;
    }

    @Override
    public String get() {
      return currentValue;
    }

    @Override
    public void set(String val) {
      setCount++;
      currentValue = val;
    }

    int getSetCount() {
      return setCount;
    }

    String getCurrentValue() {
      return currentValue;
    }
  }

  private static final class ThrowingStringCallback extends StringCallback {
    private final String currentValue;

    ThrowingStringCallback(String currentValue) {
      this.currentValue = currentValue;
    }

    @Override
    public String get() {
      return currentValue;
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      throw new InvalidConfigValueException("boom");
    }
  }
}
