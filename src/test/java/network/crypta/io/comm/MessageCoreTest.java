package network.crypta.io.comm;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Map;
import network.crypta.node.PeerTransport;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests for {@link MessageCore}. */
@ExtendWith(MockitoExtension.class)
class MessageCoreTest {

  @Mock private network.crypta.support.PriorityAwareExecutor executor;

  @Mock private Ticker ticker;

  @Mock private Dispatcher dispatcher;

  @Mock private PeerContext peerContext;

  @Captor private ArgumentCaptor<Runnable> runnableCaptor;
  @Captor private ArgumentCaptor<Long> delayCaptor;

  @Test
  @DisplayName("decodeSingleMessage returns decoded Message for valid packet")
  void decodeSingleMessage_whenValidPacket_returnsMessage() {
    MessageCore core = new MessageCore(executor);

    Message msg = DMT.createAllSent(42L);
    byte[] packet = msg.encodeToPacket();

    Message decoded = core.decodeSingleMessage(packet, 0, packet.length, peerContext, 7);

    assertNotNull(decoded, "Decoded message must not be null");
    assertEquals(DMT.allSent, decoded.getSpec());
    assertEquals(42L, decoded.getLong(DMT.UID));
  }

  @Test
  @DisplayName("decodeSingleMessage returns null when decoder throws")
  void decodeSingleMessage_whenDecoderThrows_returnsNull() {
    MessageCore core = new MessageCore(executor);

    // Passing a null buffer triggers a NullPointerException inside the decoder path.
    Message decoded = core.decodeSingleMessage(null, 0, 0, peerContext, 0);
    assertNull(decoded, "Decoder exceptions must be mapped to null");
  }

  @Test
  @DisplayName("start records time and schedules maintenance task")
  void start_recordsTimeAndSchedulesMaintenance() {
    MessageCore core = spy(new MessageCore(executor));

    core.start(ticker);

    // startedTime should be set
    assertTrue(core.getStartedTime() > 0L);

    // Initial scheduling happens with some positive delay
    verify(ticker).queueTimedJob(runnableCaptor.capture(), delayCaptor.capture());
    assertTrue(delayCaptor.getValue() >= 1L, "Expected a positive initial delay");

    // When the runnable runs, it should attempt to remove timed out filters and reschedule.
    doReturn(System.currentTimeMillis() + 2_000L).when(core).removeTimedOutFilters(anyLong());
    Runnable scheduled = runnableCaptor.getValue();
    scheduled.run();

    verify(core).removeTimedOutFilters(anyLong());
    // A second scheduling should occur; don't assert the exact value, just that it happened again.
    verify(ticker, atLeast(2)).queueTimedJob(any(Runnable.class), anyLong());
  }

  @Test
  @DisplayName("checkFilters matches existing filter and invokes callback")
  void checkFilters_whenFilterMatches_invokesCallback() throws Exception {
    MessageCore core = new MessageCore(executor);
    core.setDispatcher(dispatcher);

    // Prepare a filter that matches an allSent message with UID=123.
    MessageFilter filter =
        MessageFilter.create().setType(DMT.allSent).setField(DMT.UID, 123L).setNoTimeout();
    AsyncMessageFilterCallback cb = mock(AsyncMessageFilterCallback.class);
    filter.setAsyncCallback(cb, null);

    // Insert filter into core.
    core.addAsyncFilter(filter, cb, null);

    // Send matching message.
    Message msg = DMT.createAllSent(123L);
    core.checkFilters(msg, mock(PacketSocketHandler.class));

    // Callback must be invoked exactly once with the message.
    verify(cb, times(1)).onMatched(msg);
    // Dispatcher must not be called because the filter handled it.
    verifyNoInteractions(dispatcher);
    // Nothing should be left unclaimed.
    assertEquals(0, core.getUnclaimedFIFOSize());
  }

  @Test
  @DisplayName("checkFilters uses dispatcher and does not retain when handled")
  void checkFilters_whenDispatcherHandles_notRetained() {
    MessageCore core = new MessageCore(executor);
    core.setDispatcher(dispatcher);

    Message msg = DMT.createAllReceived(77L);
    when(dispatcher.handleMessage(msg)).thenReturn(true);

    core.checkFilters(msg, mock(PacketSocketHandler.class));

    verify(dispatcher).handleMessage(msg);
    assertEquals(0, core.getUnclaimedFIFOSize());
  }

  @Test
  @DisplayName("checkFilters retains unmatched message and counts by type")
  void checkFilters_whenUnmatched_retainedAndCounted() {
    MessageCore core = new MessageCore(executor);

    Message a = DMT.createAllReceived(1L);
    Message b = DMT.createAllReceived(2L);
    Message c = DMT.createAllSent(3L);

    core.checkFilters(a, mock(PacketSocketHandler.class));
    core.checkFilters(b, mock(PacketSocketHandler.class));
    core.checkFilters(c, mock(PacketSocketHandler.class));

    assertEquals(3, core.getUnclaimedFIFOSize());
    Map<String, Integer> counts = core.getUnclaimedFIFOMessageCounts();
    assertEquals(2, counts.get(DMT.allReceived.getName()));
    assertEquals(1, counts.get(DMT.allSent.getName()));
  }

  @Test
  @DisplayName("checkFilters rechecks after dispatcher and matches newly added filter")
  void checkFilters_whenFilterAddedDuringDispatch_matchesOnRecheck() {
    MessageCore core = new MessageCore(executor);

    Message msg = DMT.createAllSent(999L);

    // When dispatcher is called, add a matching filter that will be picked up on the recheck path.
    doAnswer(
            invocation -> {
              MessageFilter filter =
                  MessageFilter.create()
                      .setType(DMT.allSent)
                      .setField(DMT.UID, 999L)
                      .setNoTimeout();
              AsyncMessageFilterCallback cb = mock(AsyncMessageFilterCallback.class);
              when(cb.shouldTimeout()).thenReturn(false);
              filter.setAsyncCallback(cb, null);
              core.addAsyncFilter(filter, cb, null);
              return false; // Not handled by dispatcher, forces recheck path
            })
        .when(dispatcher)
        .handleMessage(msg);
    core.setDispatcher(dispatcher);

    core.checkFilters(msg, mock(PacketSocketHandler.class));

    // The dispatcher was invoked once; the filter added inside should receive onMatched.
    verify(dispatcher).handleMessage(msg);
    // Nothing remains unclaimed because the new filter matched it.
    assertEquals(0, core.getUnclaimedFIFOSize());
  }

  @Test
  @DisplayName("removeTimedOutFilters removes timed out, returns next timeout of remaining")
  void removeTimedOutFilters_removesAndReturnsNextTimeout() throws Exception {
    MessageCore core = new MessageCore(executor);

    // Filter f1 will time out via callback.shouldTimeout() being true when checked by
    // removeTimedOutFilters (timedOut()).
    MessageFilter f1 = MessageFilter.create().setType(DMT.allSent).setNoTimeout();
    AsyncMessageFilterCallback cb1 = mock(AsyncMessageFilterCallback.class);
    when(cb1.shouldTimeout()).thenReturn(true); // forces immediate timeout in reallyTimedOut()
    f1.setAsyncCallback(cb1, null);

    // Filter f2 remains and should define the next timeout value; make it match a later message.
    MessageFilter f2 =
        MessageFilter.create().setType(DMT.allSent).setField(DMT.UID, 5L).setTimeout(60_000L);
    AsyncMessageFilterCallback cb2 = mock(AsyncMessageFilterCallback.class);
    when(cb2.shouldTimeout()).thenReturn(false);
    f2.setAsyncCallback(cb2, null);

    // Add both filters to the core.
    core.addAsyncFilter(f1, cb1, null);
    core.addAsyncFilter(f2, cb2, null);

    long returnedNext = core.removeTimedOutFilters(Long.MAX_VALUE);

    // f1 should be timed out and callback invoked; f2 should remain and define next timeout.
    verify(cb1, atLeastOnce()).onTimeout();
    assertTrue(returnedNext <= f2.getTimeout());

    // Ensure f2 actually still works: deliver a matching message and expect a match.
    Message m = DMT.createAllSent(5L);
    core.checkFilters(m, mock(PacketSocketHandler.class));
    verify(cb2).onMatched(m);
  }

  @Test
  @DisplayName("onDisconnect removes matching filters and notifies callback")
  void onDisconnect_removesAndNotifies() throws Exception {
    MessageCore core = new MessageCore(executor);
    PeerContext ctx = mock(PeerContext.class);
    lenient().when(ctx.isConnected()).thenReturn(true);

    MessageFilter filter =
        MessageFilter.create().setType(DMT.allSent).setSource(ctx).setNoTimeout();
    AsyncMessageFilterCallback cb = mock(AsyncMessageFilterCallback.class);
    filter.setAsyncCallback(cb, null);

    core.addAsyncFilter(filter, cb, null);
    core.onDisconnect(ctx);

    verify(cb).onDisconnect(ctx);
  }

  @Test
  @DisplayName("onRestart removes matching filters and notifies callback")
  void onRestart_removesAndNotifies() throws Exception {
    MessageCore core = new MessageCore(executor);
    PeerContext ctx = mock(PeerContext.class);
    lenient().when(ctx.isConnected()).thenReturn(true);

    MessageFilter filter =
        MessageFilter.create().setType(DMT.allSent).setSource(ctx).setNoTimeout();
    AsyncMessageFilterCallback cb = mock(AsyncMessageFilterCallback.class);
    filter.setAsyncCallback(cb, null);

    core.addAsyncFilter(filter, cb, null);
    core.onRestart(ctx);

    verify(cb).onRestarted(ctx);
  }

  @Test
  @DisplayName("addAsyncFilter times out immediately when disconnected")
  void addAsyncFilter_whenDisconnected_throws() {
    MessageCore core = new MessageCore(executor);
    PeerContext ctx = mock(PeerContext.class);
    when(ctx.isConnected()).thenReturn(false);

    MessageFilter filter =
        MessageFilter.create().setType(DMT.allSent).setSource(ctx).setNoTimeout();
    AsyncMessageFilterCallback cb = mock(AsyncMessageFilterCallback.class);

    assertThrows(DisconnectedException.class, () -> core.addAsyncFilter(filter, cb, null));
    verifyNoInteractions(cb);
  }

  @Test
  @DisplayName("waitFor throws when filter has a callback")
  void waitFor_whenFilterHasCallback_throws() {
    MessageCore core = new MessageCore(executor);

    MessageFilter filter = MessageFilter.create().setType(DMT.allSent).setNoTimeout();
    filter.setAsyncCallback(mock(AsyncMessageFilterCallback.class), null);

    assertThrows(IllegalArgumentException.class, () -> core.waitFor(filter, null));
  }

  @Test
  @DisplayName("waitFor returns immediately when message already unclaimed and updates counter")
  void waitFor_whenMessageAlreadyUnclaimed_returnsAndCountsBytes() throws Exception {
    MessageCore core = new MessageCore(executor);

    // First, feed an unmatched message so it lands in the unclaimed FIFO.
    Message msg = DMT.createAllSent(777L);
    core.checkFilters(msg, mock(PacketSocketHandler.class));
    assertEquals(1, core.getUnclaimedFIFOSize());

    // Now wait for a matching filter; no callback is allowed for waitFor.
    MessageFilter filter =
        MessageFilter.create().setType(DMT.allSent).setField(DMT.UID, 777L).setNoTimeout();

    ByteCounter ctr = mock(ByteCounter.class);
    Message result = core.waitFor(filter, ctr);

    assertNotNull(result, "Should receive the pre-queued message");
    assertEquals(0, core.getUnclaimedFIFOSize(), "Unclaimed FIFO must be drained by the match");
    // Locally constructed message encodes to 0 received-bytes; verify accounting still invoked.
    verify(ctr).receivedBytes(result.receivedByteCount());
  }

  @Test
  @DisplayName("send delegates to PeerContext for non-internal types and skips internal-only")
  void send_delegatesOrSkipsInternalOnly() throws Exception {
    MessageCore core = new MessageCore(executor);

    PeerContext dest = mock(PeerContext.class);
    PeerTransport transport = mock(PeerTransport.class);
    when(dest.transport()).thenReturn(transport);

    // Non-internal message is sent via PeerContext.sendAsync.
    Message normal = DMT.createAllReceived(123L);
    ByteCounter ctr = mock(ByteCounter.class);
    core.send(dest, normal, ctr);
    verify(transport).sendAsync(normal, null, ctr);

    // Internal-only message must be skipped.
    Message internal = DMT.createTestReceiveCompleted(1L, true, "ok");
    clearInvocations(dest, transport);
    core.send(dest, internal, ctr);
    verifyNoInteractions(dest, transport);
  }
}
