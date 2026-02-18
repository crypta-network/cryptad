package network.crypta.node;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class UIDTagHardTimeoutTest {

  private static final long UID = 4242L;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private RequestTracker tracker;

  @BeforeEach
  void setup() {
    when(node.routing().tracker()).thenReturn(tracker);
  }

  @Test
  void hardTimeout_whenTimedOutContinueAndHandlerUnlocked_triggersFatalTimeoutOnce() {
    TestUIDTag tag = new TestUIDTag(node, UID);
    PeerNode peer = mock(PeerNode.class);

    tag.addRoutedTo(peer, /* offeredKey= */ false);
    tag.timedOutToHandlerButContinued();
    tag.unlockHandler();

    long now = System.currentTimeMillis() + RequestTracker.TIMEOUT + 1_000;
    tag.maybeLogStillPresent(now, UID);

    verify(peer, times(1)).fatalTimeout(tag, false);

    tag.maybeLogStillPresent(now + RequestTracker.TIMEOUT, UID);
    verify(peer, times(1)).fatalTimeout(tag, false);
  }

  @Test
  void hardTimeout_beforeGraceWindow_doesNotTriggerFatalTimeout() {
    TestUIDTag tag = new TestUIDTag(node, UID);
    PeerNode peer = mock(PeerNode.class);

    tag.addRoutedTo(peer, /* offeredKey= */ false);
    tag.timedOutToHandlerButContinued();
    tag.unlockHandler();

    long now = System.currentTimeMillis() + RequestTracker.TIMEOUT - 5_000;
    tag.maybeLogStillPresent(now, UID);

    verify(peer, never()).fatalTimeout(tag, false);
  }

  private static final class TestUIDTag extends UIDTag {
    private TestUIDTag(Node node, long uid) {
      super(/* source= */ null, /* realTimeFlag= */ false, uid, node);
    }

    @Override
    public void logStillPresent(Long uid) {
      // Intentionally empty for test isolation.
    }

    @Override
    public int expectedTransfersIn(
        boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
      return 0;
    }

    @Override
    public int expectedTransfersOut(
        boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
      return 0;
    }

    @Override
    public boolean isSSK() {
      return false;
    }

    @Override
    public boolean isInsert() {
      return false;
    }

    @Override
    public boolean isOfferReply() {
      return false;
    }
  }
}
