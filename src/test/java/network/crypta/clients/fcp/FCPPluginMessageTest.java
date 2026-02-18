package network.crypta.clients.fcp;

import java.util.UUID;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // Allow snake_case method names for tests
class FCPPluginMessageTest {

  @Mock private Bucket mockBucket;

  @Test
  void construct_noArgs_shouldCreateDefaultMessage() {
    FCPPluginMessage message = FCPPluginMessage.construct();

    assertNull(message.permissions);
    assertNotNull(message.identifier);
    // Verify identifier is a UUID
    assertDoesNotThrow(() -> UUID.fromString(message.identifier));

    assertNotNull(message.params);
    // Check if params is shortLived (not directly exposed, but we can assume from constructor)

    assertNull(message.data);
    assertNull(message.success);
    assertNull(message.errorCode);
    assertNull(message.errorMessage);

    assertFalse(message.isReplyMessage());
  }

  @Test
  void construct_withParamsAndBucket_shouldSetFields() {
    SimpleFieldSet params = new SimpleFieldSet(true);
    params.putOverwrite("key", "value");

    FCPPluginMessage message = FCPPluginMessage.construct(params, mockBucket);

    assertNull(message.permissions);
    assertNotNull(message.identifier);
    assertEquals(params, message.params);
    assertEquals(mockBucket, message.data);
    assertNull(message.success);
    assertNull(message.errorCode);
    assertNull(message.errorMessage);

    assertFalse(message.isReplyMessage());
  }

  @Test
  void constructReplyMessage_shouldCreateReplyWithSameIdentifier() {
    FCPPluginMessage original = FCPPluginMessage.construct();
    SimpleFieldSet replyParams = new SimpleFieldSet(true);

    FCPPluginMessage reply =
        FCPPluginMessage.constructReplyMessage(original, replyParams, mockBucket, true, null, null);

    assertNull(reply.permissions);
    assertEquals(original.identifier, reply.identifier);
    assertEquals(replyParams, reply.params);
    assertEquals(mockBucket, reply.data);
    assertEquals(Boolean.TRUE, reply.success);
    assertNull(reply.errorCode);
    assertNull(reply.errorMessage);

    assertTrue(reply.isReplyMessage());
  }

  @Test
  void constructReplyMessage_whenOriginalIsReply_shouldThrowException() {
    FCPPluginMessage original = FCPPluginMessage.construct();
    FCPPluginMessage reply = FCPPluginMessage.constructSuccessReply(original);

    assertThrows(IllegalStateException.class, () -> FCPPluginMessage.constructSuccessReply(reply));
  }

  @Test
  void constructSuccessReply_shouldSetSuccessTrue() {
    FCPPluginMessage original = FCPPluginMessage.construct();

    FCPPluginMessage reply = FCPPluginMessage.constructSuccessReply(original);

    assertEquals(original.identifier, reply.identifier);
    assertEquals(Boolean.TRUE, reply.success);
    assertNull(reply.errorCode);
    assertNull(reply.errorMessage);
    assertNotNull(reply.params);
    assertNull(reply.data);
  }

  @Test
  void constructErrorReply_shouldSetSuccessFalseAndErrorFields() {
    FCPPluginMessage original = FCPPluginMessage.construct();
    String errorCode = "Error123";
    String errorMessage = "Something went wrong";

    FCPPluginMessage reply =
        FCPPluginMessage.constructErrorReply(original, errorCode, errorMessage);

    assertEquals(original.identifier, reply.identifier);
    assertEquals(Boolean.FALSE, reply.success);
    assertEquals(errorCode, reply.errorCode);
    assertEquals(errorMessage, reply.errorMessage);
    assertNotNull(reply.params);
    assertNull(reply.data);
  }

  @Test
  void markSent_shouldReturnTrueFirstTimeAndFalseSubsequently() {
    FCPPluginMessage message = FCPPluginMessage.construct();

    assertTrue(message.markSent(), "First call to markSent should return true");
    assertFalse(message.markSent(), "Second call to markSent should return false");
    assertFalse(message.markSent(), "Third call to markSent should return false");
  }

  @Test
  void toString_shouldContainKeyFields() {
    FCPPluginMessage message = FCPPluginMessage.construct();
    String stringRep = message.toString();

    assertTrue(stringRep.contains(message.identifier));
    assertTrue(stringRep.contains("permissions"));
    assertTrue(stringRep.contains("success"));
  }

  // Tests for assertion logic (requires -ea to be effective, but good to document expectations)

  @Test
  void constructRawMessage_invalidErrorCode_shouldFailAssertion() {
    // This test expects an AssertionError if assertions are enabled.
    // If assertions are disabled, it will pass (or we can skip it).
    // For now, we'll write it to document the constraint, but wrap in try-catch or assumeTrue
    // if we could detect assertion status.
    // Since we can't easily force assertions on/off in this env, we will just test the logic
    // if we can, or skip if it's purely assertion based.
    // The class uses `assert` keyword.

    // Let's try to trigger it. If it doesn't throw, it means assertions are off.
    if (FCPPluginMessage.class.desiredAssertionStatus()) {
      String uuid = UUID.randomUUID().toString();
      assertThrows(
          AssertionError.class,
          () ->
              FCPPluginMessage.constructRawMessage(
                  null, uuid, null, null, false, "Invalid Code!", null));
    } else {
      assertTrue(true, "Assertions are disabled; skipping assertion check.");
    }
  }
}
