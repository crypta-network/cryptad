package network.crypta.clients.fcp;

import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@SuppressWarnings("java:S100") // test naming convention: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class FCPPluginServerMessageTest {

  @Mock private Bucket bucket;

  @Mock private FCPConnectionHandler handler;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void constructor_withBucket_setsDataLengthAndMakesBucketReadOnly() {
    long expectedLength = 123L;
    org.mockito.Mockito.lenient().when(bucket.size()).thenReturn(expectedLength);

    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, bucket, null, null, null);

    assertEquals(expectedLength, message.dataLength());
    assertEquals("Data", message.getEndString());
    verify(bucket).setReadOnly();
    verify(bucket).size();
  }

  @Test
  void constructor_withNullBucket_setsNegativeDataLengthAndEndMessage() {
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, null, null, null);

    assertEquals(-1L, message.dataLength());
    assertEquals("EndMessage", message.getEndString());
  }

  @Test
  void getFieldSet_withoutBucketParamsOrSuccess_producesMinimalFields() {
    String pluginName = "TestPlugin";
    String identifier = "test-id";

    FCPPluginServerMessage message =
        new FCPPluginServerMessage(pluginName, identifier, null, null, null, null, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(pluginName, fieldSet.get("PluginName"));
    assertEquals(identifier, fieldSet.get("Identifier"));
    assertNull(fieldSet.get("DataLength"));
    assertNull(fieldSet.get("Success"));
    assertNull(fieldSet.get("ErrorCode"));
    assertNull(fieldSet.get("ErrorMessage"));
    assertNull(fieldSet.subset(FCPPluginServerMessage.PARAM_PREFIX));
  }

  @Test
  void getFieldSet_withPositiveDataLength_addsDataLengthField() {
    long expectedLength = 42L;
    org.mockito.Mockito.lenient().when(bucket.size()).thenReturn(expectedLength);

    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, bucket, null, null, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(String.valueOf(expectedLength), fieldSet.get("DataLength"));
  }

  @Test
  void getFieldSet_withEmptyParams_doesNotAddRepliesSubset() {
    SimpleFieldSet plugParams = new SimpleFieldSet(true);

    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", plugParams, null, null, null, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.subset(FCPPluginServerMessage.PARAM_PREFIX));
  }

  @Test
  void getFieldSet_withNonEmptyParams_addsRepliesSubset() {
    SimpleFieldSet plugParams = new SimpleFieldSet(true);
    plugParams.putSingle("Key", "Value");

    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", plugParams, null, null, null, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    SimpleFieldSet repliesSubset = fieldSet.subset(FCPPluginServerMessage.PARAM_PREFIX);
    assertNotNull(repliesSubset);
    assertEquals("Value", repliesSubset.get("Key"));
  }

  @Test
  void getFieldSet_withSuccessNull_omitsSuccessAndErrorFields() {
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, null, "ERR", "msg");

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertNull(fieldSet.get("Success"));
    assertNull(fieldSet.get("ErrorCode"));
    assertNull(fieldSet.get("ErrorMessage"));
  }

  @Test
  void getFieldSet_withSuccessTrue_setsSuccessWithoutErrorFields() {
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, true, "ERR", "msg");

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("true", fieldSet.get("Success"));
    assertNull(fieldSet.get("ErrorCode"));
    assertNull(fieldSet.get("ErrorMessage"));
  }

  @Test
  void getFieldSet_withSuccessFalseAndNoErrorCode_setsSuccessOnly() {
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, false, null, "ignored");

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("false", fieldSet.get("Success"));
    assertNull(fieldSet.get("ErrorCode"));
    assertNull(fieldSet.get("ErrorMessage"));
  }

  @Test
  void getFieldSet_withSuccessFalseAndErrorCodeOnly_setsSuccessAndErrorCode() {
    String errorCode = "TestErrorCode";
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, false, errorCode, null);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("false", fieldSet.get("Success"));
    assertEquals(errorCode, fieldSet.get("ErrorCode"));
    assertNull(fieldSet.get("ErrorMessage"));
  }

  @Test
  void getFieldSet_withSuccessFalseAndErrorCodeAndMessage_setsAllErrorFields() {
    String errorCode = "TestErrorCode";
    String errorMessage = "Test error message";
    FCPPluginServerMessage message =
        new FCPPluginServerMessage(
            "TestPlugin", "test-id", null, null, false, errorCode, errorMessage);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("false", fieldSet.get("Success"));
    assertEquals(errorCode, fieldSet.get("ErrorCode"));
    assertEquals(errorMessage, fieldSet.get("ErrorMessage"));
  }

  @Test
  void constructor_withPluginMessage_copiesFieldsFromMessage() {
    FCPPluginMessage request = FCPPluginMessage.construct();
    request.params.putOverwrite("originalKey", "originalValue");

    FCPPluginMessage reply =
        FCPPluginMessage.constructErrorReply(request, "ReplyError", "Reply message");
    reply.params.putOverwrite("replyKey", "replyValue");

    String pluginName = "TestPlugin";
    FCPPluginServerMessage message = new FCPPluginServerMessage(pluginName, reply);

    assertEquals(reply.identifier, message.getIdentifier());
    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals(pluginName, fieldSet.get("PluginName"));
    assertEquals(reply.identifier, fieldSet.get("Identifier"));
    assertEquals("false", fieldSet.get("Success"));
    assertEquals("ReplyError", fieldSet.get("ErrorCode"));
    assertEquals("Reply message", fieldSet.get("ErrorMessage"));

    SimpleFieldSet repliesSubset = fieldSet.subset(FCPPluginServerMessage.PARAM_PREFIX);
    assertNotNull(repliesSubset);
    assertEquals(reply.params.toOrderedString(), repliesSubset.toOrderedString());
  }

  @Test
  void getName_returnsProtocolName() {
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, null, null, null);

    assertEquals("FCPPluginReply", message.getName());
  }

  @Test
  void isGlobal_alwaysReturnsFalse() {
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, null, null, null);

    assertFalse(message.isGlobal());
  }

  @Test
  void getIdentifier_returnsIdentifierPassedToConstructor() {
    String identifier = "my-identifier";
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", identifier, null, null, null, null, null);

    assertEquals(identifier, message.getIdentifier());
  }

  @Test
  void run_alwaysThrowsMessageInvalidExceptionWithExpectedDetails() {
    FCPPluginServerMessage message =
        new FCPPluginServerMessage("TestPlugin", "test-id", null, null, null, null, null);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler, node));

    assertEquals(
        "FCPPluginReply goes from server to client not the other way around",
        exception.getMessage());
    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, exception.protocolCode);
    assertNull(exception.ident);
    assertFalse(exception.global);

    verifyNoInteractions(handler, node);
  }
}
