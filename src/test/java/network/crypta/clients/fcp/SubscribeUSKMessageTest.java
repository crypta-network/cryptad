package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import network.crypta.client.async.USKManager;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SubscribeUSKMessageTest {

  private static final String VALID_USK_URI =
      "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,"
          + "3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/Ultimate-Freenet-Index/55/";

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore nodeClientCore;
  @Mock private USKManager uskManager;
  @Mock private FCPConnectionHandler handler;
  @Mock private PersistentRequestClient rebootClient;
  @Mock private RequestClient requestClient;

  @Test
  void constructor_whenIdentifierMissing_throwsMessageInvalidException() {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("URI", VALID_USK_URI);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new SubscribeUSKMessage(fields));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertNull(exception.ident);
    assertEquals("No Identifier!", exception.getMessage());
  }

  @Test
  void constructor_whenUriMissing_throwsMessageInvalidException() {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("Identifier", "my-id");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new SubscribeUSKMessage(fields));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("my-id", exception.ident);
    assertEquals("Expected a URI on SubscribeUSK", exception.getMessage());
  }

  @Test
  void constructor_whenUriMalformed_throwsMessageInvalidException() {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("Identifier", "bad-uri-id");
    fields.putSingle("URI", "not-a-valid-usk");

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> new SubscribeUSKMessage(fields));

    assertEquals(ProtocolErrorMessage.INVALID_FIELD, exception.protocolCode);
    assertEquals("bad-uri-id", exception.ident);
    assertTrue(exception.getMessage().contains("Could not parse URI"));
  }

  @Test
  void constructor_whenPriorityClassMissing_usesDefaultsAndDerivedProgress() throws Exception {
    SimpleFieldSet fields = baseFields();

    SubscribeUSKMessage message = new SubscribeUSKMessage(fields);

    assertEquals(RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS, message.prio);
    assertEquals((short) 3, message.prioProgress);
    assertFalse(message.dontPoll);
    assertFalse(message.sparsePoll);
    assertFalse(message.realTimeFlag);
    assertFalse(message.ignoreUSKDatehints);
    assertNotNull(message.key);
  }

  @Test
  void constructor_whenDontPollTrueSparsePollIgnored_setsFlagsFromFieldSet() throws Exception {
    SimpleFieldSet fields = baseFields();
    fields.put("DontPoll", true);
    fields.put("SparsePoll", true); // Should be ignored because DontPoll is true.
    fields.putSingle("PriorityClass", Short.toString(RequestStarter.UPDATE_PRIORITY_CLASS));
    fields.putSingle("PriorityClassProgress", "1");
    fields.put("RealTimeFlag", true);
    fields.put("IgnoreUSKDatehints", true);

    SubscribeUSKMessage message = new SubscribeUSKMessage(fields);

    assertEquals("identifier", message.clientIdentifier);
    assertTrue(message.dontPoll);
    assertFalse(message.sparsePoll);
    assertEquals(RequestStarter.UPDATE_PRIORITY_CLASS, message.prio);
    assertEquals((short) 1, message.prioProgress);
    assertTrue(message.realTimeFlag);
    assertTrue(message.ignoreUSKDatehints);
  }

  @Test
  void getFieldSet_whenCalled_returnsUriAndDontPoll() throws Exception {
    SimpleFieldSet fields = baseFields();
    fields.put("DontPoll", true);
    SubscribeUSKMessage message = new SubscribeUSKMessage(fields);

    SimpleFieldSet result = message.getFieldSet();

    assertEquals(message.key.getURI().toString(), result.get("URI"));
    assertTrue(result.getBoolean("DontPoll", false));
    assertNull(result.get("Identifier"));
  }

  @Test
  void run_whenSubscriptionSucceeds_sendsSubscribedUSKMessage() throws Exception {
    wireHandlerForSuccessfulSubscribe();
    SubscribeUSKMessage message = new SubscribeUSKMessage(baseFields());

    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    lenient().when(node.services()).thenReturn(services);
    lenient().when(services.clientCore()).thenReturn(nodeClientCore);
    when(nodeClientCore.getUskManager()).thenReturn(uskManager);
    doNothing().when(uskManager).subscribe(any(), any(), anyBoolean(), anyBoolean(), any());

    message.run(handler, node);

    ArgumentCaptor<FCPMessage> captor = ArgumentCaptor.forClass(FCPMessage.class);
    verify(handler).send(captor.capture());
    FCPMessage sent = captor.getValue();
    SubscribedUSKMessage subscribed = assertInstanceOf(SubscribedUSKMessage.class, sent);
    assertEquals(message.clientIdentifier, subscribed.message.clientIdentifier);
  }

  @Test
  void run_whenIdentifierCollides_sendsIdentifierCollisionMessage() throws Exception {
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    lenient().when(node.services()).thenReturn(services);
    lenient().when(services.clientCore()).thenReturn(nodeClientCore);
    doThrow(new IdentifierCollisionException())
        .when(handler)
        .addUSKSubscription(any(), any(SubscribeUSK.class));

    SubscribeUSKMessage message = new SubscribeUSKMessage(baseFields());

    message.run(handler, node);

    verify(handler).send(isA(IdentifierCollisionMessage.class));
    verify(handler, never()).send(isA(SubscribedUSKMessage.class));
  }

  private SimpleFieldSet baseFields() {
    SimpleFieldSet fields = new SimpleFieldSet(true);
    fields.putSingle("Identifier", "identifier");
    fields.putSingle("URI", VALID_USK_URI);
    return fields;
  }

  private void wireHandlerForSuccessfulSubscribe() throws IdentifierCollisionException {
    lenient().when(handler.getRebootClient()).thenReturn(rebootClient);
    lenient().when(rebootClient.lowLevelClient(false)).thenReturn(requestClient);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    lenient().when(node.services()).thenReturn(services);
    lenient().when(services.clientCore()).thenReturn(nodeClientCore);
    doNothing().when(handler).addUSKSubscription(any(), any(SubscribeUSK.class));
  }
}
