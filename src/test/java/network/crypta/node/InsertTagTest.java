package network.crypta.node;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test naming style: method_whenCondition_expectOutcome
class InsertTagTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PeerNode source;
  @Mock private PeerManager peerManager;
  @Mock private Ticker ticker;

  private TestRequestTracker tracker;

  // Lightweight tracker that records unlock calls made by UIDTag.innerUnlock(...)
  static class TestRequestTracker extends RequestTracker {
    boolean unlocked;
    boolean noRecordFlag;
    UIDTag unlockedTag;
    int unlockCount;

    TestRequestTracker(PeerManager peers, Ticker ticker) {
      super(peers, ticker);
    }

    @Override
    void unlockUID(UIDTag tag, boolean canFail, boolean noRecord) {
      // Record the call only; avoid mutating internal maps for isolation.
      unlocked = true;
      unlockedTag = tag;
      noRecordFlag = noRecord;
      unlockCount++;
    }
  }

  @BeforeEach
  void setUp() {
    tracker = new TestRequestTracker(peerManager, ticker);
    when(node.routing().tracker()).thenReturn(tracker);
  }

  @Test
  void expectedTransfersIn_whenNotAccepted_returnsZero() {
    InsertTag tag = new InsertTag(true, InsertTag.START.REMOTE, source, false, 1L, node);
    // Remote request defaults to not accepted
    int in = tag.expectedTransfersIn(false, 3, true);
    assertEquals(0, in);
  }

  @Test
  void expectedTransfersIn_whenAcceptedLocal_ignoreFalse_returnsZero() {
    InsertTag tag = new InsertTag(false, InsertTag.START.LOCAL, null, false, 2L, node);
    // Local requests are marked accepted in UIDTag's constructor
    int in = tag.expectedTransfersIn(false, 3, true);
    assertEquals(0, in);
  }

  @Test
  void expectedTransfersIn_whenAcceptedLocal_ignoreTrue_returnsOne() {
    InsertTag tag = new InsertTag(false, InsertTag.START.LOCAL, null, false, 3L, node);
    int in = tag.expectedTransfersIn(true, 3, true);
    assertEquals(1, in);
  }

  @Test
  void expectedTransfersIn_whenAcceptedRemote_returnsOne() {
    InsertTag tag = new InsertTag(true, InsertTag.START.REMOTE, source, false, 4L, node);
    tag.setAccepted();
    int in = tag.expectedTransfersIn(false, 2, true);
    assertEquals(1, in);
  }

  @Test
  void expectedTransfersOut_whenNotAccepted_returnsZero() {
    InsertTag tag = new InsertTag(true, InsertTag.START.REMOTE, source, false, 5L, node);
    int out = tag.expectedTransfersOut(false, 5, true);
    assertEquals(0, out);
  }

  @Test
  void expectedTransfersOut_whenAcceptedAndNotRoutedOnwards_returnsOutwardTransfersPerInsert() {
    InsertTag tag = new InsertTag(false, InsertTag.START.LOCAL, null, false, 6L, node);
    int out = tag.expectedTransfersOut(false, 7, true);
    assertEquals(7, out);
  }

  @Test
  void expectedTransfersOut_whenAcceptedButNotRoutedOnwardsFlagSet_returnsZero() {
    InsertTag tag = new InsertTag(false, InsertTag.START.LOCAL, null, false, 7L, node);
    tag.setNotRoutedOnwards();
    int out = tag.expectedTransfersOut(false, 7, true);
    assertEquals(0, out);
  }

  @Test
  void identityFlags_areCorrect() {
    InsertTag tagSSK = new InsertTag(true, InsertTag.START.REMOTE, source, false, 8L, node);
    InsertTag tagCHK = new InsertTag(false, InsertTag.START.LOCAL, null, true, 9L, node);

    assertTrue(tagSSK.isSSK());
    assertFalse(tagCHK.isSSK());
    assertTrue(tagSSK.isInsert());
    assertTrue(tagCHK.isInsert());
    assertFalse(tagSSK.isOfferReply());
    assertFalse(tagCHK.isOfferReply());
  }

  @Test
  void finishedSender_whenHandlerUnlockedAndSenderStarted_triggersUnlockWithNoRecordFlag() {
    InsertTag tag = new InsertTag(true, InsertTag.START.REMOTE, source, true, 10L, node);

    // Arrange: started sender and unlocked handler with noRecord=true
    tag.startedSender();
    tag.unlockHandler(true);

    // Act
    tag.finishedSender();

    // Assert: innerUnlock delegates to tracker.unlockUID with the same noRecord flag
    assertTrue(tracker.unlocked);
    assertSame(tag, tracker.unlockedTag);
    assertTrue(tracker.noRecordFlag);
    assertEquals(1, tracker.unlockCount);
  }

  @Test
  void finishedSender_whenHandlerNotUnlocked_doesNotUnlock() {
    InsertTag tag = new InsertTag(false, InsertTag.START.LOCAL, null, false, 11L, node);
    tag.startedSender();

    tag.finishedSender();

    assertFalse(tracker.unlocked);
  }

  @Test
  void unlockHandler_whenSenderNotFinished_doesNotUnlockUntilFinished() {
    InsertTag tag = new InsertTag(true, InsertTag.START.REMOTE, source, false, 12L, node);

    tag.startedSender();
    tag.unlockHandler(false); // super.mustUnlock() is blocked by InsertTag.mustUnlock()
    assertFalse(tracker.unlocked);

    tag.finishedSender();
    assertTrue(tracker.unlocked);
    assertFalse(tracker.noRecordFlag);
  }

  @Test
  void finishedSender_whenOutstandingRouting_defersUntilRoutingRemoved() {
    InsertTag tag = new InsertTag(false, InsertTag.START.REMOTE, source, false, 13L, node);
    PeerNode next = source; // any non-null peer reference is fine

    tag.startedSender();
    tag.unlockHandler(false);
    // Simulate we are still routing to a peer
    tag.addRoutedTo(next, false);

    tag.finishedSender();
    assertFalse(tracker.unlocked, "Should not unlock while still routing");

    // When routing ceases, UIDTag.removeRoutingTo should cause unlock
    tag.removeRoutingTo(next);
    assertTrue(tracker.unlocked);
    assertEquals(1, tracker.unlockCount);
  }

  @Test
  void logStillPresent_withoutThrowable_logsErrorWithoutThrowable() {
    InsertTag tag = new InsertTag(true, InsertTag.START.LOCAL, null, false, 14L, node);

    Logger logger = (Logger) LoggerFactory.getLogger(InsertTag.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);

    try {
      tag.logStillPresent(42L);
      List<ILoggingEvent> events = appender.list;
      assertFalse(events.isEmpty());
      ILoggingEvent last = events.getLast();
      assertEquals(Level.ERROR, last.getLevel());
      // Message contains UID and fields; do not assert the elapsed-time prefix exactly
      String msg = last.getFormattedMessage();
      assertTrue(msg.contains(" : 42 "));
      assertTrue(msg.contains(" ssk="));
      assertTrue(msg.contains(" start="));
      assertNull(last.getThrowableProxy());
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }

  @Test
  void logStillPresent_withThrowable_logsErrorWithThrowable() {
    InsertTag tag = new InsertTag(false, InsertTag.START.REMOTE, source, true, 15L, node);

    Logger logger = (Logger) LoggerFactory.getLogger(InsertTag.class);
    ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    logger.addAppender(appender);

    try {
      RuntimeException boom = new RuntimeException("boom");
      tag.handlerThrew(boom);
      tag.logStillPresent(99L);

      List<ILoggingEvent> events = appender.list;
      assertFalse(events.isEmpty());
      ILoggingEvent last = events.getLast();
      assertEquals(Level.ERROR, last.getLevel());
      String msg = last.getFormattedMessage();
      assertTrue(msg.contains(" : 99 "));
      assertTrue(msg.contains(" ssk="));
      assertTrue(msg.contains(" start="));
      // Throwable is attached
      assertTrue(
          last.getThrowableProxy() != null
              && last.getThrowableProxy().getMessage().contains("boom"));
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }
}
