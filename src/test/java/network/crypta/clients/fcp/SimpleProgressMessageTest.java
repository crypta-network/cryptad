package network.crypta.clients.fcp;

import java.time.Instant;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.client.events.SplitfileProgressTimestamps;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class SimpleProgressMessageTest {

  private static final String IDENTIFIER = "req-123";
  private static final Instant SUCCESS_TIME = Instant.ofEpochMilli(1_700_000_000_000L);
  private static final Instant FAILURE_TIME = Instant.ofEpochMilli(1_700_000_100_000L);

  @Test
  void getFieldSet_whenMinSuccessFetchZero_excludesOptionalField() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(10, 4, 2, 1, 6, 0, true),
            new SplitfileProgressTimestamps(SUCCESS_TIME, FAILURE_TIME));
    SimpleProgressMessage message = new SimpleProgressMessage(IDENTIFIER, true, event);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("10", fieldSet.get("Total"));
    assertEquals("6", fieldSet.get("Required"));
    assertEquals("2", fieldSet.get("Failed"));
    assertEquals("1", fieldSet.get("FatallyFailed"));
    assertEquals("4", fieldSet.get("Succeeded"));
    assertEquals(Long.toString(SUCCESS_TIME.toEpochMilli()), fieldSet.get("LastProgress"));
    assertEquals("true", fieldSet.get("FinalizedTotal"));
    assertEquals(IDENTIFIER, fieldSet.get("Identifier"));
    assertEquals("true", fieldSet.get("Global"));
    assertNull(fieldSet.get("MinSuccessFetchBlocks"));
  }

  @Test
  void getFieldSet_whenMinSuccessFetchPresent_includesOptionalField() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(8, 2, 1, 0, 5, 3, false),
            new SplitfileProgressTimestamps(null, null));
    SimpleProgressMessage message = new SimpleProgressMessage("other", false, event);

    SimpleFieldSet fieldSet = message.getFieldSet();

    assertEquals("3", fieldSet.get("MinSuccessFetchBlocks"));
    assertEquals("0", fieldSet.get("LastProgress"));
    assertEquals("false", fieldSet.get("Global"));
  }

  @Test
  void run_whenInvoked_throwsMessageInvalidException() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(1, 0, 0, 0, 1, 0, false),
            new SplitfileProgressTimestamps(null, null));
    SimpleProgressMessage message = new SimpleProgressMessage(IDENTIFIER, true, event);

    MessageInvalidException thrown =
        assertThrows(MessageInvalidException.class, () -> message.run(null, null));

    assertEquals(ProtocolErrorMessage.INVALID_MESSAGE, thrown.protocolCode);
    assertEquals(IDENTIFIER, thrown.ident);
    assertEquals(
        "SimpleProgress goes from server to client not the other way around", thrown.getMessage());
    assertTrue(thrown.global);
  }

  @Test
  void getFraction_whenPartialProgress_returnsRatio() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(20, 5, 0, 0, 10, 0, false),
            new SplitfileProgressTimestamps(SUCCESS_TIME, null));
    SimpleProgressMessage message = new SimpleProgressMessage(IDENTIFIER, false, event);

    assertEquals(0.25d, message.getFraction(), 1e-9);
  }

  @Test
  void getLatestSuccess_whenRead_matchesEventValue() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(5, 3, 0, 0, 4, 0, false),
            new SplitfileProgressTimestamps(SUCCESS_TIME, null));
    SimpleProgressMessage message = new SimpleProgressMessage(IDENTIFIER, false, event);

    assertEquals(SUCCESS_TIME, message.getLatestSuccess());
  }

  @Test
  void getLatestFailure_whenRead_matchesEventValue() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(5, 3, 0, 1, 4, 0, false),
            new SplitfileProgressTimestamps(SUCCESS_TIME, FAILURE_TIME));
    SimpleProgressMessage message = new SimpleProgressMessage(IDENTIFIER, false, event);

    assertEquals(FAILURE_TIME, message.getLatestFailure());
  }

  @Test
  void getters_whenCalled_returnUnderlyingCounts() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            new SplitfileProgressCounts(12, 9, 2, 1, 10, 4, true),
            new SplitfileProgressTimestamps(SUCCESS_TIME, FAILURE_TIME));
    SimpleProgressMessage message = new SimpleProgressMessage(IDENTIFIER, true, event);

    assertEquals(0.75d, message.getFraction(), 1e-9);
    assertEquals(10, message.getMinBlocks());
    assertEquals(12, message.getTotalBlocks());
    assertEquals(9, message.getFetchedBlocks());
    assertEquals(2, message.getFailedBlocks());
    assertEquals(1, message.getFatalyFailedBlocks());
    assertEquals(FAILURE_TIME, message.getLatestFailure());
    assertEquals(SUCCESS_TIME, message.getLatestSuccess());
    assertTrue(message.isTotalFinalized());
    assertEquals("SimpleProgress", message.getName());
  }
}
