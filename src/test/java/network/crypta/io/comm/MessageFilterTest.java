package network.crypta.io.comm;

import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.node.PrioRunnable;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Unit tests for {@link MessageFilter}. */
@ExtendWith(MockitoExtension.class)
class MessageFilterTest {

  private static final AtomicInteger TYPE_SEQ = new AtomicInteger();

  @Mock private PriorityAwareExecutor executor;

  @Captor private ArgumentCaptor<Runnable> runnableCaptor;

  private static MessageType newType(String base, Object... fieldPairs) {
    // fieldPairs: even indices = name (String); odd indices = Class<?>
    MessageType t =
        new MessageType(
            "MessageFilterTest_" + base + "_" + TYPE_SEQ.incrementAndGet(),
            /* priority= */ (short) 5);
    for (int i = 0; i + 1 < fieldPairs.length; i += 2) {
      String name = (String) fieldPairs[i];
      Class<?> type = (Class<?>) fieldPairs[i + 1];
      t.addField(name, type);
    }
    return t;
  }

  @Test
  @DisplayName("setSource_and_getSource roundtrip")
  void setSource_whenSet_returnsSame() {
    MessageFilter f = MessageFilter.create().setType(newType("source-type"));
    PeerContext ctx = mock(PeerContext.class);
    assertSame(f, f.setSource(ctx));
    assertSame(ctx, f.getSource());
  }

  @Test
  @DisplayName("setField overloads store values that match() verifies")
  void match_whenAllTypedFieldsEqual_returnsMATCHED() {
    MessageType t =
        newType(
            "typed",
            "b",
            Boolean.class,
            "y",
            Byte.class,
            "s",
            Short.class,
            "i",
            Integer.class,
            "l",
            Long.class);
    MessageFilter f =
        MessageFilter.create()
            .setType(t)
            .setField("b", true)
            .setField("y", (byte) 1)
            .setField("s", (short) 2)
            .setField("i", 3)
            .setField("l", 4L)
            .setNoTimeout();

    Message m = new Message(t);
    m.set("b", true);
    m.set("y", (byte) 1);
    m.set("s", (short) 2);
    m.set("i", 3);
    m.set("l", 4L);

    assertEquals(MessageFilter.MATCHED.FOUND, f.match(m, System.currentTimeMillis()));
  }

  @Test
  @DisplayName("setField wrong type throws IncorrectTypeException and unknown field throws ISE")
  void setField_whenWrongTypeOrUnknown_throws() {
    MessageType t = newType("wrong-type", "name", String.class);
    MessageFilter f = MessageFilter.create().setType(t);

    assertThrows(IncorrectTypeException.class, () -> f.setField("name", 123L));
    assertThrows(IllegalStateException.class, () -> f.setField("unknown", "x"));
  }

  @Test
  @DisplayName("setField null value throws NPE (delegated) when type is set")
  void setField_whenNull_throwsNullPointer() {
    MessageType t = newType("null-val", "x", String.class);
    MessageFilter f = MessageFilter.create().setType(t);
    assertThrows(NullPointerException.class, () -> f.setField("x", null));
  }

  @Test
  @DisplayName("or chaining delegates to right-hand first and respects different timeouts")
  void or_whenRightMatches_returnsRightResult() {
    MessageType leftT = newType("or-left");
    MessageType rightT = newType("or-right", "id", Long.class);

    MessageFilter left = MessageFilter.create().setType(leftT).setTimeout(1_000L);
    MessageFilter right =
        MessageFilter.create().setType(rightT).setField("id", 1L).setTimeout(2_000L);

    // Combine; warning about different timeouts is logged but not thrown.
    left.or(right);

    Message msg = new Message(rightT);
    msg.set("id", 1L);

    MessageFilter.MATCHED res = left.match(msg, System.currentTimeMillis());
    assertEquals(MessageFilter.MATCHED.FOUND, res);
  }

  @Test
  @DisplayName("or called twice with different filters throws")
  void or_whenSecondDifferent_throws() {
    MessageFilter a = MessageFilter.create().setType(newType("or-a")).setNoTimeout();
    MessageFilter b = MessageFilter.create().setType(newType("or-b")).setNoTimeout();
    MessageFilter c = MessageFilter.create().setType(newType("or-c")).setNoTimeout();

    a.or(b);
    IllegalStateException ex = assertThrows(IllegalStateException.class, () -> a.or(c));
    assertTrue(ex.getMessage().contains("Setting a second .or()"));
  }

  @Test
  @DisplayName("match returns NONE or TIMED_OUT on type/source mismatch depending on time")
  void match_whenTypeOrSourceMismatch_returnsNoneOrTimedOut() {
    MessageType t1 = newType("m1");
    MessageType t2 = newType("m2");
    MessageFilter f = MessageFilter.create().setType(t1).setNoTimeout();

    Message mWrongType = new Message(t2);
    assertEquals(MessageFilter.MATCHED.NONE, f.match(mWrongType, System.currentTimeMillis()));

    // Now make it timed out.
    MessageFilter f2 = MessageFilter.create().setType(t1).setTimeout(0L);
    long now = System.currentTimeMillis() + 1L;
    assertEquals(MessageFilter.MATCHED.TIMED_OUT, f2.match(mWrongType, now));

    // Source mismatch also yields NONE/TIMED_OUT accordingly.
    PeerContext srcA = mock(PeerContext.class);
    PeerContext srcB = mock(PeerContext.class);
    Message mRightTypeWrongSrc = new Message(t1);
    mRightTypeWrongSrc = spy(mRightTypeWrongSrc);
    doReturn(srcB).when(mRightTypeWrongSrc).getSource();

    assertEquals(
        MessageFilter.MATCHED.NONE,
        f.setSource(srcA).match(mRightTypeWrongSrc, System.currentTimeMillis()));
    assertEquals(
        MessageFilter.MATCHED.TIMED_OUT, f2.setSource(srcA).match(mRightTypeWrongSrc, now));
  }

  @Test
  @DisplayName("match returns NONE/TIMED_OUT when a required field is missing or value differs")
  void match_whenFieldMissingOrDifferent_returnsNoneOrTimedOut() {
    MessageType t = newType("fields", "x", Long.class);
    MessageFilter f = MessageFilter.create().setType(t).setField("x", 1L).setNoTimeout();
    MessageFilter fTimed = MessageFilter.create().setType(t).setField("x", 1L).setTimeout(0L);
    Message m = new Message(t);

    long now = System.currentTimeMillis() + 1L;
    assertEquals(MessageFilter.MATCHED.NONE, f.match(m, now));
    assertEquals(MessageFilter.MATCHED.TIMED_OUT, fTimed.match(m, now));

    // Set a different value -> mismatch
    m.set("x", 2L);
    assertEquals(MessageFilter.MATCHED.NONE, f.match(m, now));
  }

  @Test
  @DisplayName("match honors noTimeout flag and ignores immediate timeout request")
  void match_whenNoTimeoutTrue_ignoresShouldTimeout() {
    MessageType t = newType("no-timeout", "x", Long.class);
    MessageFilter f = MessageFilter.create().setType(t).setField("x", 9L).setTimeout(0L);

    Message m = new Message(t);
    m.set("x", 9L);

    AsyncMessageFilterCallback cb = mock(AsyncMessageFilterCallback.class);
    f.setAsyncCallback(cb, null);

    // Because noTimeout=true, shouldTimeout() must not be consulted.
    MessageFilter.MATCHED res = f.match(m, /* noTimeout= */ true, System.currentTimeMillis());
    assertEquals(MessageFilter.MATCHED.FOUND, res);
    verifyNoInteractions(cb);

    // Without noTimeout and with an immediate-timeout signal, we should see TIMED_OUT_AND_MATCHED.
    when(cb.shouldTimeout()).thenReturn(true);
    assertEquals(
        MessageFilter.MATCHED.TIMED_OUT_AND_MATCHED,
        f.match(m, /* noTimeout= */ false, System.currentTimeMillis()));
  }

  @Test
  @DisplayName("setMessage marks matched and getMessage returns it")
  void setMessage_whenCalled_setsMatchedAndMessage() {
    MessageType t = newType("set-msg");
    MessageFilter f = MessageFilter.create().setType(t).setNoTimeout();
    Message m = new Message(t);

    f.setMessage(m);
    assertTrue(f.matched());
    assertSame(m, f.getMessage());
  }

  @Test
  @DisplayName("clearMatched resets state and cascades to or-chain")
  void clearMatched_whenCalled_resetsAndCascades() {
    MessageType t1 = newType("clear-left");
    MessageType t2 = newType("clear-right");
    MessageFilter left = MessageFilter.create().setType(t1).setNoTimeout();
    MessageFilter right = MessageFilter.create().setType(t2).setNoTimeout();
    left.or(right);

    Message m = new Message(t2);
    right.setMessage(m);
    assertTrue(right.matched());

    left.clearMatched();
    assertFalse(right.matched());
    assertNull(right.getMessage());
  }

  @Test
  @DisplayName("clearOr removes chained filter and disables delegation")
  void clearOr_whenCalled_removesChain() {
    MessageType leftT = newType("clr-left");
    MessageType rightT = newType("clr-right", "id", Long.class);
    MessageFilter left = MessageFilter.create().setType(leftT).setNoTimeout();
    MessageFilter right = MessageFilter.create().setType(rightT).setField("id", 5L).setNoTimeout();
    left.or(right);
    left.clearOr();

    Message m = new Message(rightT);
    m.set("id", 5L);
    // No delegation after clearOr -> left does not match since type differs.
    assertEquals(MessageFilter.MATCHED.NONE, left.match(m, System.currentTimeMillis()));
  }

  @Test
  @DisplayName("matchesDroppedConnection/restarted use identity and recurse into or-chain")
  void matchesDroppedAndRestarted_whenSourceMatchesOrChain_true() {
    PeerContext a = mock(PeerContext.class);
    PeerContext b = mock(PeerContext.class);

    MessageFilter left = MessageFilter.create().setType(newType("m-drop-left")).setSource(a);
    MessageFilter right = MessageFilter.create().setType(newType("m-drop-right")).setSource(b);
    left.or(right);

    assertTrue(left.matchesDroppedConnection(a));
    assertTrue(left.matchesRestartedConnection(b));
    assertFalse(left.matchesDroppedConnection(mock(PeerContext.class)));
  }

  @Test
  @DisplayName("onDroppedConnection sets flag and dispatches slow callback via executor")
  void onDroppedConnection_whenSlowCallback_dispatchesViaExecutor() {
    MessageFilter f = MessageFilter.create().setType(newType("onDrop")).setNoTimeout();
    PeerContext ctx = mock(PeerContext.class);

    SlowAsyncMessageFilterCallback cb = mock(SlowAsyncMessageFilterCallback.class);
    when(cb.getPriority()).thenReturn(5);
    f.setAsyncCallback(cb, null);

    f.onDroppedConnection(ctx, executor);
    assertSame(ctx, f.droppedConnection());

    verify(executor).execute(runnableCaptor.capture());
    Runnable r = runnableCaptor.getValue();
    assertInstanceOf(PrioRunnable.class, r);
    assertEquals(5, ((PrioRunnable) r).getPriority());
    r.run();
    verify(cb).onDisconnect(ctx);
  }

  @Test
  @DisplayName("onRestartedConnection dispatches slow callback via executor")
  void onRestartedConnection_whenSlowCallback_dispatchesViaExecutor() {
    MessageFilter f = MessageFilter.create().setType(newType("onRestart")).setNoTimeout();
    PeerContext ctx = mock(PeerContext.class);

    SlowAsyncMessageFilterCallback cb = mock(SlowAsyncMessageFilterCallback.class);
    when(cb.getPriority()).thenReturn(7);
    f.setAsyncCallback(cb, null);

    f.onRestartedConnection(ctx, executor);
    verify(executor).execute(runnableCaptor.capture());
    Runnable r = runnableCaptor.getValue();
    assertInstanceOf(PrioRunnable.class, r);
    assertEquals(7, ((PrioRunnable) r).getPriority());
    r.run();
    verify(cb).onRestarted(ctx);
  }

  @Test
  @DisplayName("onMatched clears state, dispatches slow callback, and accounts bytes")
  void onMatched_whenSlowCallback_dispatchesAndCountsBytes() {
    MessageType t = newType("onMatched", "v", Long.class);
    MessageFilter f = MessageFilter.create().setType(t).setField("v", 1L).setNoTimeout();

    // Prepare a locally created message (receivedByteCount() == 0 is fine for this test).
    Message m = new Message(t);
    m.set("v", 1L);
    f.setMessage(m);

    SlowAsyncMessageFilterCallback cb = mock(SlowAsyncMessageFilterCallback.class);
    when(cb.getPriority()).thenReturn(3);
    ByteCounter ctr = mock(ByteCounter.class);
    f.setAsyncCallback(cb, ctr);

    f.onMatched(executor);

    verify(executor).execute(runnableCaptor.capture(), anyString());
    Runnable r = runnableCaptor.getValue();
    assertInstanceOf(PrioRunnable.class, r);
    // Priority obtained from callback stub
    assertEquals(3, ((PrioRunnable) r).getPriority());
    r.run();
    verify(cb).onMatched(m);
    verify(ctr).receivedBytes(m.receivedByteCount());
  }

  @Test
  @DisplayName("onTimedOut dispatches slow callback via executor")
  void onTimedOut_whenSlowCallback_dispatchesViaExecutor() {
    MessageFilter f = MessageFilter.create().setType(newType("onTimeout")).setNoTimeout();

    SlowAsyncMessageFilterCallback cb = mock(SlowAsyncMessageFilterCallback.class);
    when(cb.getPriority()).thenReturn(9);
    f.setAsyncCallback(cb, null);

    f.onTimedOut(executor);
    verify(executor).execute(runnableCaptor.capture());
    Runnable r = runnableCaptor.getValue();
    assertInstanceOf(PrioRunnable.class, r);
    assertEquals(9, ((PrioRunnable) r).getPriority());
    r.run();
    verify(cb).onTimeout();
  }

  @Test
  @DisplayName(
      "anyConnectionsDropped returns true when disconnected or bootID changes; false when matched")
  void anyConnectionsDropped_variousCases() {
    MessageFilter f = MessageFilter.create().setType(newType("acd")).setNoTimeout();

    // When already matched -> always false
    f.setMessage(new Message(newType("acd-msg")));
    assertFalse(f.anyConnectionsDropped());

    // Reset matched state and set a connected source
    f.clearMatched();
    PeerContext ctx = mock(PeerContext.class);
    when(ctx.isConnected()).thenReturn(false);
    f.setSource(ctx);
    assertTrue(f.anyConnectionsDropped());

    // Connected but boot ID changed
    PeerContext ctx2 = mock(PeerContext.class);
    when(ctx2.isConnected()).thenReturn(true);
    when(ctx2.getBootID()).thenReturn(1L, 2L);
    f.setSource(ctx2);
    assertTrue(f.anyConnectionsDropped());

    // Chain with or()
    MessageFilter other = MessageFilter.create().setType(newType("acd-or")).setNoTimeout();
    other.setSource(ctx);
    f.clearOr();
    f.or(other);
    assertTrue(f.anyConnectionsDropped());
  }

  @Test
  @DisplayName("hasCallback reflects whether callback is set")
  void hasCallback_whenSet_trueOtherwiseFalse() {
    MessageFilter f = MessageFilter.create().setType(newType("hc")).setNoTimeout();
    assertFalse(f.hasCallback());
    f.setAsyncCallback(mock(AsyncMessageFilterCallback.class), null);
    assertTrue(f.hasCallback());
  }

  @Test
  @DisplayName("toString contains message type name")
  void toString_whenTypeSet_containsTypeName() {
    MessageType t = newType("tostr");
    MessageFilter f = MessageFilter.create().setType(t).setNoTimeout();
    String s = f.toString();
    assertTrue(s.contains(t.getName()));
  }

  @Test
  @DisplayName("onStartWaiting throws without timeout and when waiting on callback")
  void onStartWaiting_whenInvalidState_throws() {
    MessageFilter f = MessageFilter.create().setType(newType("osw"));
    assertThrows(IllegalStateException.class, () -> f.onStartWaiting(true));

    f.setNoTimeout();
    f.setAsyncCallback(mock(AsyncMessageFilterCallback.class), null);
    assertThrows(IllegalStateException.class, () -> f.onStartWaiting(true));
  }

  @Test
  @DisplayName(
      "waitForSignalOrTimeout returns null on immediate timeout and returns message when matched")
  void waitForSignalOrTimeout_variousOutcomes() throws Exception {
    // Immediate timeout path
    MessageFilter f1 = MessageFilter.create().setType(newType("wfsot1")).setTimeout(0L);
    Message m1 = f1.waitForSignalOrTimeout();
    assertNull(m1);

    // Already matched path
    MessageType t = newType("wfsot2");
    MessageFilter f2 = MessageFilter.create().setType(t).setNoTimeout();
    Message m = new Message(t);
    f2.setMessage(m);
    assertSame(m, f2.waitForSignalOrTimeout());

    // Dropped connection throws
    MessageFilter f3 = MessageFilter.create().setType(newType("wfsot3")).setNoTimeout();
    PeerContext ctx = mock(PeerContext.class);
    f3.onDroppedConnection(ctx, executor);
    assertThrows(DisconnectedException.class, f3::waitForSignalOrTimeout);
  }
}
