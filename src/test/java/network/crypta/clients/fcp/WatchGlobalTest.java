package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class WatchGlobalTest {

  @Mock private FCPConnectionHandler handler;
  @Mock private PersistentRequestClient rebootClient;
  @Mock private PersistentRequestClient foreverClient;
  @Mock private Node node;
  @Mock private FCPServer handlerFcpServer;

  @Test
  void constructor_withValidFields_setsEnabledAndVerbosityMask() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", false);
    fs.put("VerbosityMask", 7);

    WatchGlobal watchGlobal = new WatchGlobal(fs);

    SimpleFieldSet result = watchGlobal.getFieldSet();
    assertFalse(result.getBoolean("Enabled", true));
    assertEquals(7, result.getInt("VerbosityMask", -1));
  }

  @Test
  void constructor_withoutFields_defaultsEnabledTrueAndMaxVerbosity() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    WatchGlobal watchGlobal = new WatchGlobal(fs);

    SimpleFieldSet result = watchGlobal.getFieldSet();
    assertTrue(result.getBoolean("Enabled", false));
    assertEquals(Integer.MAX_VALUE, result.getInt("VerbosityMask", -1));
  }

  @Test
  void constructor_withInvalidVerbosityMask_throwsMessageInvalidException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("VerbosityMask", "not-a-number");

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> new WatchGlobal(fs));

    assertEquals(ProtocolErrorMessage.ERROR_PARSING_NUMBER, thrown.protocolCode);
    assertTrue(thrown.getMessage().contains("not-a-number"));
  }

  @Test
  void getName_returnsWatchGlobalConstant() throws Exception {
    WatchGlobal watchGlobal = new WatchGlobal(new SimpleFieldSet(true));

    assertEquals("WatchGlobal", watchGlobal.getName());
  }

  @Test
  void run_whenRebootSetWatchGlobalFails_sendsProtocolErrorAndUpdatesForeverClient()
      throws Exception {
    prepareSharedMocks();
    when(rebootClient.setWatchGlobal(true, 3, handlerFcpServer)).thenReturn(false);
    when(handler.getForeverClient()).thenReturn(foreverClient);

    WatchGlobal watchGlobal = new WatchGlobal(fieldSet(true, 3));

    watchGlobal.run(handler, node);

    ArgumentCaptor<FCPMessage> messageCaptor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(messageCaptor.capture());
    ProtocolErrorMessage error = (ProtocolErrorMessage) messageCaptor.getValue();
    SimpleFieldSet errorFs = error.getFieldSet();
    assertEquals(ProtocolErrorMessage.PERSISTENCE_DISABLED, errorFs.getInt("Code", -1));
    assertFalse(errorFs.getBoolean("Fatal", true));
    assertTrue(errorFs.getBoolean("Global", false));
    assertEquals("Persistence disabled", errorFs.get("ExtraDescription"));

    verify(rebootClient).setWatchGlobal(true, 3, handlerFcpServer);
    verify(foreverClient).setWatchGlobal(true, 3, handlerFcpServer);
  }

  @Test
  void run_whenForeverClientMissing_skipsForeverWatchWithoutError() throws Exception {
    prepareSharedMocks();
    when(rebootClient.setWatchGlobal(false, 9, handlerFcpServer)).thenReturn(true);
    when(handler.getForeverClient()).thenReturn(null);

    WatchGlobal watchGlobal = new WatchGlobal(fieldSet(false, 9));

    watchGlobal.run(handler, node);

    verify(rebootClient).setWatchGlobal(false, 9, handlerFcpServer);
    verify(handler, never()).send(any(FCPMessage.class));
    verify(handler).getRebootClient();
    verify(handler).getForeverClient();
  }

  @Test
  void run_whenSetWatchGlobalSucceeds_updatesBothClientsWithHandlerServer() throws Exception {
    prepareSharedMocks();
    when(rebootClient.setWatchGlobal(false, 7, handlerFcpServer)).thenReturn(true);
    when(handler.getForeverClient()).thenReturn(foreverClient);

    WatchGlobal watchGlobal = new WatchGlobal(fieldSet(false, 7));

    watchGlobal.run(handler, node);

    verify(rebootClient).setWatchGlobal(false, 7, handlerFcpServer);
    verify(foreverClient).setWatchGlobal(false, 7, handlerFcpServer);
    verify(handler, never()).send(any(FCPMessage.class));
  }

  private void prepareSharedMocks() {
    when(handler.getRebootClient()).thenReturn(rebootClient);
    when(handler.getServer()).thenReturn(handlerFcpServer);
  }

  private SimpleFieldSet fieldSet(boolean enabled, int verbosityMask) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", enabled);
    fs.put("VerbosityMask", verbosityMask);
    return fs;
  }
}
