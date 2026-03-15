package network.crypta.clients.fcp;

import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SubscribedUSKMessageTest {

  private static final String TEST_USK =
      "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/FakeM3UHostingFreesite/23/";

  @Mock private FCPConnectionHandler handler;

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void getFieldSet_whenBuiltFromSubscribeMessage_expectIdentifierUriAndDontPollPresent(
      boolean dontPoll) throws Exception {
    SubscribeUSKMessage subscribe = buildSubscribeUSKMessage("id-" + dontPoll, dontPoll);
    SubscribedUSKMessage message = new SubscribedUSKMessage(subscribe);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNotNull(fieldSet);
    assertEquals("id-" + dontPoll, fieldSet.get("Identifier"));
    assertEquals(subscribe.key.getURI().toString(), fieldSet.get("URI"));
    assertEquals(Boolean.toString(dontPoll), fieldSet.get("DontPoll"));
  }

  @Test
  void getName_always_returnsSubscribedUSK() throws Exception {
    SubscribedUSKMessage message = new SubscribedUSKMessage(buildSubscribeUSKMessage("id", true));

    assertEquals(SubscribedUSKMessage.NAME, message.getName());
  }

  @Test
  void run_whenCalled_expectMessageInvalidExceptionWithProtocolDetails() throws Exception {
    SubscribedUSKMessage message = new SubscribedUSKMessage(buildSubscribeUSKMessage("id", false));

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertEquals(
        "SubscribedUSK goes from server to client not the other way around",
        exception.getMessage());
    assertEquals(SubscribedUSKMessage.NAME, exception.ident);
    assertFalse(exception.global);
  }

  private SubscribeUSKMessage buildSubscribeUSKMessage(String identifier, boolean dontPoll)
      throws MessageInvalidException {
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle("Identifier", identifier);
    fieldSet.putSingle("URI", TEST_USK);
    fieldSet.put("DontPoll", dontPoll);
    return new SubscribeUSKMessage(fieldSet);
  }
}
