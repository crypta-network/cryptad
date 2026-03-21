package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class WatchFeedsMessageTest {

  @Mock private FcpMessageRuntimeSupport messageRuntimeSupport;
  @Mock private FCPConnectionHandler handler;
  @Mock private FCPServer server;

  @Test
  void constructor_whenEnabledMissing_defaultsToTrue() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    WatchFeedsMessage message = new WatchFeedsMessage(fs);

    assertTrue(message.enabled);
  }

  @Test
  void constructor_whenEnabledFalse_parsesFalse() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", false);

    WatchFeedsMessage message = new WatchFeedsMessage(fs);

    assertFalse(message.enabled);
  }

  @Test
  void constructor_whenEnabledInvalidValue_defaultsToTrue() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Enabled", "maybe");

    WatchFeedsMessage message = new WatchFeedsMessage(fs);

    assertTrue(message.enabled);
  }

  @Test
  void run_whenEnabledTrue_watchesConnection() throws MessageInvalidException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", true);
    WatchFeedsMessage message = new WatchFeedsMessage(fs);

    when(handler.getServer()).thenReturn(server);
    when(server.messageRuntimeSupport()).thenReturn(messageRuntimeSupport);

    message.run(handler);

    verify(messageRuntimeSupport).watchFeeds(handler, true);
  }

  @Test
  void run_whenDisabled_unwatchesConnection() throws MessageInvalidException {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", false);
    WatchFeedsMessage message = new WatchFeedsMessage(fs);

    when(handler.getServer()).thenReturn(server);
    when(server.messageRuntimeSupport()).thenReturn(messageRuntimeSupport);

    message.run(handler);

    verify(messageRuntimeSupport).watchFeeds(handler, false);
  }

  @Test
  void getFieldSet_whenCalled_containsEnabledFlag() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("Enabled", false);
    WatchFeedsMessage message = new WatchFeedsMessage(fs);

    SimpleFieldSet result = message.getFieldSet();

    assertFalse(result.getBoolean("Enabled", true));
  }

  @Test
  void getName_always_returnsConstant() {
    WatchFeedsMessage message = new WatchFeedsMessage(new SimpleFieldSet(true));

    assertEquals(WatchFeedsMessage.NAME, message.getName());
  }
}
