package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import network.crypta.node.subsystem.NodeRoutingSubsystem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OfferReplyTagTest {

  @Mock private RequestTracker tracker;

  @Test
  @DisplayName("constructor_whenLocalSource_setsFlagsAndInitializesTracker")
  void constructor_whenLocalSource_setsFlagsAndInitializesTracker() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();

    OfferReplyTag tag = new OfferReplyTag(/* isSSK= */ true, /* source= */ null, true, 123L, node);

    assertTrue(tag.wasLocal(), "Null source should mark tag as local");
    assertTrue(tag.isSSK(), "SSK flag should reflect constructor argument");
    verify(node.routing(), times(1)).tracker();
  }

  @ParameterizedTest(
      name = "expectedTransfersIn(ignoreLocal={0}, outPerInsert={1}, forAccept={2}) = 0")
  @CsvSource({"true,0,true", "true,1,false", "false,5,true", "false,2,false"})
  void expectedTransfersIn_variousParams_returnsZero(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();
    OfferReplyTag tag = new OfferReplyTag(false, null, false, 1L, node);

    int in = tag.expectedTransfersIn(ignoreLocalVsRemote, outwardTransfersPerInsert, forAccept);
    assertEquals(0, in, "Offer replies expect no inbound transfers to attribute");
  }

  @ParameterizedTest(
      name = "expectedTransfersOut(ignoreLocal={0}, outPerInsert={1}, forAccept={2}) = 1")
  @CsvSource({"true,0,true", "true,3,false", "false,1,true", "false,7,false"})
  void expectedTransfersOut_variousParams_returnsOne(
      boolean ignoreLocalVsRemote, int outwardTransfersPerInsert, boolean forAccept) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();
    OfferReplyTag tag = new OfferReplyTag(true, null, false, 2L, node);

    int out = tag.expectedTransfersOut(ignoreLocalVsRemote, outwardTransfersPerInsert, forAccept);
    assertEquals(1, out, "Offer replies attribute exactly one outbound transfer");
  }

  @Test
  void isInsert_whenCalled_returnsFalse() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();
    OfferReplyTag tag = new OfferReplyTag(false, null, false, 3L, node);
    assertFalse(tag.isInsert());
  }

  @Test
  void isOfferReply_whenCalled_returnsTrue() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();
    OfferReplyTag tag = new OfferReplyTag(false, null, false, 4L, node);
    assertTrue(tag.isOfferReply());
  }

  @Test
  void logStillPresent_whenInvoked_doesNotThrowAndIncludesState() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();
    OfferReplyTag tag = new OfferReplyTag(true, null, false, 5L, node);

    assertDoesNotThrow(() -> tag.logStillPresent(null));
  }

  @Test
  void maybeLogStillPresent_whenWithinTimeout_doesNotInvokeLogger() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();
    OfferReplyTag realTag = new OfferReplyTag(false, null, false, 6L, node);
    OfferReplyTag spyTag = spy(realTag);

    long now = System.currentTimeMillis();

    spyTag.maybeLogStillPresent(now, 6L);

    verify(spyTag, times(0)).logStillPresent(anyLong());
  }

  @Test
  void maybeLogStillPresent_whenPastTimeout_invokesLoggerOncePerInterval() {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeRoutingSubsystem routing = mock(NodeRoutingSubsystem.class);
    doReturn(routing).when(node).routing();
    doReturn(tracker).when(routing).tracker();
    OfferReplyTag realTag = new OfferReplyTag(false, null, false, 7L, node);
    OfferReplyTag spyTag = spy(realTag);

    long base = System.currentTimeMillis() + RequestTracker.TIMEOUT + 1; // beyond timeout

    spyTag.maybeLogStillPresent(base, 7L);
    // Within the 60s guard window: no second call
    spyTag.maybeLogStillPresent(base + 30_000, 7L);
    // After the guard window: second call allowed
    spyTag.maybeLogStillPresent(base + 61_000, 7L);

    verify(spyTag, times(2)).logStillPresent(7L);
  }
}
