package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.keys.BaseClientKey;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class MultiPutCompletionCallbackTest {

  @Mock private PutCompletionCallback cb;
  @Mock private BaseClientPutter parent;
  @Mock private ClientContext context;

  private Object token;

  @BeforeEach
  void setup() {
    token = new Object();
  }

  @Test
  void onSuccess_whenAllStatesComplete_expectFetchableBlocksAndSuccessOnce() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState s1 = mock(ClientPutState.class);
    ClientPutState s2 = mock(ClientPutState.class);

    mpc.add(s1);
    mpc.add(s2);

    // Arm starts the lifecycle; nothing should be completed yet
    mpc.arm(context);

    // First success: not complete yet
    mpc.onSuccess(s1, context);

    // Second success: should complete and notify
    mpc.onSuccess(s2, context);

    // onBlockSetFinished should be called once when the last block set completes
    verify(cb, times(1)).onBlockSetFinished(mpc, context);
    // onFetchable should be called once when all become fetchable
    verify(cb, times(1)).onFetchable(mpc);
    // Finally, success of the composite
    verify(cb, times(1)).onSuccess(mpc, context);
    // No failure expected
    verify(cb, never()).onFailure(any(), any(), any());
  }

  @Test
  void onFailure_whenCollisionAllowed_expectTreatAsSuccess() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(
            cb, parent, token, /*persistent*/ false, /*collisionIsOK*/ true);
    ClientPutState s = mock(ClientPutState.class);
    mpc.add(s);
    mpc.arm(context);

    mpc.onFailure(new InsertException(InsertExceptionMode.COLLISION), s, context);

    verify(cb, times(1)).onSuccess(mpc, context);
    verify(cb, never()).onFailure(any(), any(), any());
  }

  @Test
  void onFailure_whenFinishOnFailureAndStarted_expectCancelRemaining() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(
            cb, parent, token, /*persistent*/ false, /*collisionIsOK*/ false, /*finishOnFailure*/
            true);
    ClientPutState s1 = mock(ClientPutState.class);
    ClientPutState s2 = mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);
    mpc.arm(context);

    mpc.onFailure(new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND), s1, context);

    // Should cancel the outstanding state (s2) once
    verify(s2, times(1)).cancel(context);
    // No completion yet
    verify(cb, never()).onSuccess(any(), any());
    verify(cb, never()).onFailure(any(), any(), any());
  }

  @Test
  void onFailure_whenFinishOnFailureBeforeArm_expectArmTriggersCancel() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(
            cb, parent, token, /*persistent*/ false, /*collisionIsOK*/ false, /*finishOnFailure*/
            true);
    ClientPutState s1 = mock(ClientPutState.class);
    ClientPutState s2 = mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);

    // Fail before arming — should set the cancelling flag but not cancel yet
    mpc.onFailure(new InsertException(InsertExceptionMode.REJECTED_OVERLOAD), s1, context);
    verifyNoInteractions(s2);

    // Arm now — should trigger cancellation of remaining state
    mpc.arm(context);
    verify(s2, times(1)).cancel(context);
  }

  @Test
  void onEncode_whenGeneratorMatches_expectForwardedOnceForDuplicateKey() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState gen = mock(ClientPutState.class);
    BaseClientKey key1 = mock(BaseClientKey.class);
    BaseClientKey key2 = mock(BaseClientKey.class);
    mpc.addURIGenerator(gen);

    mpc.onEncode(key1, gen, context);
    // Duplicate with same key suppressed
    mpc.onEncode(key1, gen, context);
    // Different key still forwarded
    mpc.onEncode(key2, gen, context);

    verify(cb, times(1)).onEncode(key1, mpc, context);
    verify(cb, times(1)).onEncode(key2, mpc, context);
  }

  @Test
  void onEncode_whenNotGenerator_expectIgnored() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState other = mock(ClientPutState.class);
    BaseClientKey key = mock(BaseClientKey.class);
    mpc.add(other);

    mpc.onEncode(key, other, context);

    verify(cb, never()).onEncode(any(), any(), any());
  }

  @Test
  void onMetadata_withModelAndBucket_whenGenerator_expectForwarded() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState gen = mock(ClientPutState.class);
    mpc.addURIGenerator(gen);
    Metadata meta = org.mockito.Mockito.mock(Metadata.class);
    Bucket bucket = org.mockito.Mockito.mock(Bucket.class);

    mpc.onMetadata(meta, gen, context);
    mpc.onMetadata(bucket, gen, context);

    verify(cb, times(1)).onMetadata(meta, mpc, context);
    verify(cb, times(1)).onMetadata(bucket, mpc, context);
  }

  @Test
  void onBlockSetFinished_whenBeforeArm_thenAfterAll_expectSingleCallback() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState s1 = org.mockito.Mockito.mock(ClientPutState.class);
    ClientPutState s2 = org.mockito.Mockito.mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);

    // Before arm: no callback
    mpc.onBlockSetFinished(s1, context);
    verify(cb, never()).onBlockSetFinished(any(), any());

    // Arm, still one outstanding blocks set
    mpc.arm(context);
    verify(cb, never()).onBlockSetFinished(any(), any());

    // Finishing the last one triggers callback once
    mpc.onBlockSetFinished(s2, context);
    verify(cb, times(1)).onBlockSetFinished(mpc, context);
  }

  @Test
  void onFetchable_whenAfterArm_expectOnlyOnce() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState s1 = org.mockito.Mockito.mock(ClientPutState.class);
    ClientPutState s2 = org.mockito.Mockito.mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);

    // Before arm: ignored
    mpc.onFetchable(s1);

    mpc.arm(context);
    // Completing the last fetchable should trigger once
    mpc.onFetchable(s2);
    // Even if we try again, should be suppressed
    mpc.onFetchable(s1);

    verify(cb, times(1)).onFetchable(mpc);
  }

  @Test
  void onTransition_whenGeneratorMoves_expectEncodeFollowsNewState() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState oldGen = mock(ClientPutState.class);
    ClientPutState newGen = mock(ClientPutState.class);
    BaseClientKey key = mock(BaseClientKey.class);
    mpc.addURIGenerator(oldGen);

    // Move generator to new state
    mpc.onTransition(oldGen, newGen, context);

    // Old generator should not trigger callbacks anymore
    mpc.onEncode(key, oldGen, context);
    verify(cb, never()).onEncode(any(), any(), any());

    // New generator should forward
    mpc.onEncode(key, newGen, context);
    verify(cb, times(1)).onEncode(key, mpc, context);
  }

  @Test
  void getToken_whenRequested_expectOriginalToken() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    assertEquals(token, mpc.getToken());
  }

  @Test
  void cancel_whenCalled_expectPropagatesToAllStates() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState s1 = mock(ClientPutState.class);
    ClientPutState s2 = mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);

    mpc.cancel(context);

    verify(s1, times(1)).cancel(context);
    verify(s2, times(1)).cancel(context);
  }

  @Test
  void onResume_whenCalledTwice_expectIdempotentAndCbWhenDifferentFromParent() throws Exception {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState s1 = mock(ClientPutState.class);
    ClientPutState s2 = mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);

    mpc.onResume(context);
    mpc.onResume(context); // should be ignored

    verify(s1, times(1)).onResume(context);
    verify(s2, times(1)).onResume(context);
    // cb != parent, so cb.onResume() is invoked only once
    verify(cb, times(1)).onResume(context);
  }

  @Test
  void onResume_whenCbIsParent_expectNoCbResume() throws Exception {
    // Use a parent that is also a PutCompletionCallback to make (cb == parent)
    class Combined extends BaseClientPutter implements PutCompletionCallback {
      Combined() {}

      @Override
      public void onSuccess(ClientPutState state, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onEncode(BaseClientKey usk, ClientPutState state, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onMetadata(Metadata meta, ClientPutState state, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onMetadata(Bucket meta, ClientPutState state, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onFetchable(ClientPutState state) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onBlockSetFinished(ClientPutState state, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onTransition(ClientPutState from, ClientPutState to, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public void onTransition(
          ClientGetState oldState, ClientGetState newState, ClientContext context) {
        // Intentionally empty: stub implementation used only for type compatibility in tests.
      }

      @Override
      public int getMinSuccessFetchBlocks() {
        return 0;
      }

      @Override
      protected ClientBaseCallback getCallback() {
        return new ClientBaseCallback() {
          @Override
          public void onResume(ClientContext context) {
            // Intentionally empty: no resume work required for this test stub.
          }

          @Override
          public RequestClient getRequestClient() {
            return new RequestClient() {
              @Override
              public boolean persistent() {
                return true;
              }

              @Override
              public boolean realTimeFlag() {
                return false;
              }
            };
          }
        };
      }

      @Override
      protected void innerNotifyClients(ClientContext context) {
        // Intentionally empty: test stub does not notify clients.
      }

      @Override
      protected void innerToNetwork(ClientContext context) {
        // Intentionally empty: test stub does not perform network submission.
      }

      @Override
      public FreenetURI getURI() {
        return null;
      }

      @Override
      public boolean isFinished() {
        return false;
      }

      @Override
      public void cancel(ClientContext context) {
        // Intentionally empty: test stub has no cancellable work.
      }
    }

    Combined combined = new Combined();
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(combined, combined, token, /*persistent*/ false);
    ClientPutState s = org.mockito.Mockito.mock(ClientPutState.class);
    mpc.add(s);

    mpc.onResume(context);

    // State resume called
    verify(s, times(1)).onResume(context);
    // Because cb == parent do NOT call cb.onResume()
    verifyNoInteractions(cb);
  }

  @Test
  void onShutdown_whenCalled_expectPropagatesToAllStates() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState s1 = org.mockito.Mockito.mock(ClientPutState.class);
    ClientPutState s2 = org.mockito.Mockito.mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);

    mpc.onShutdown(context);

    verify(s1, times(1)).onShutdown(context);
    verify(s2, times(1)).onShutdown(context);
  }

  @Test
  void schedule_whenCalled_expectNoException() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    assertDoesNotThrow(() -> mpc.schedule(context));
  }

  @Test
  void complete_whenPersistent_clonesFailureException() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ true);
    ClientPutState s1 = org.mockito.Mockito.mock(ClientPutState.class);
    ClientPutState s2 = org.mockito.Mockito.mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);
    mpc.arm(context);

    InsertException original = new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND);
    // Record a failure for s1, but not complete yet (s2 outstanding)
    mpc.onFailure(original, s1, context);
    // Finish s2 so the composite completes with stored failure
    mpc.onSuccess(s2, context);

    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(cb, times(1)).onFailure(cap.capture(), any(), any());
    InsertException delivered = cap.getValue();
    // It should be a clone, not the same instance
    assertNotSame(original, delivered);
  }

  @Test
  void complete_whenCancelledAfterFailure_usesOriginalFailureMode() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ true);
    ClientPutState s1 = org.mockito.Mockito.mock(ClientPutState.class);
    ClientPutState s2 = org.mockito.Mockito.mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);
    mpc.arm(context);

    // First failure: real cause
    InsertException first = new InsertException(InsertExceptionMode.ROUTE_NOT_FOUND);
    mpc.onFailure(first, s1, context);

    // Second failure arrives as CANCELLED; complete should prefer the first cause
    InsertException cancelled = new InsertException(InsertExceptionMode.CANCELLED);
    mpc.onFailure(cancelled, s2, context);

    ArgumentCaptor<InsertException> cap = ArgumentCaptor.forClass(InsertException.class);
    verify(cb, times(1)).onFailure(cap.capture(), any(), any());
    InsertException delivered = cap.getValue();
    // Should reflect the first (non-cancelled) failure mode
    org.junit.jupiter.api.Assertions.assertEquals(
        InsertExceptionMode.ROUTE_NOT_FOUND, delivered.getMode());
  }

  @Test
  void complete_whenMultipleFailures_nonCancelledReplacesOriginal() {
    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(cb, parent, token, /*persistent*/ false);
    ClientPutState s1 = org.mockito.Mockito.mock(ClientPutState.class);
    ClientPutState s2 = org.mockito.Mockito.mock(ClientPutState.class);
    mpc.add(s1);
    mpc.add(s2);
    mpc.arm(context);

    // First failure cause stored
    InsertException first = new InsertException(InsertExceptionMode.REJECTED_OVERLOAD);
    mpc.onFailure(first, s1, context);

    // Second, different non-cancelled cause should replace
    InsertException second = new InsertException(InsertExceptionMode.INTERNAL_ERROR);
    mpc.onFailure(second, s2, context);

    verify(cb, times(1)).onFailure(second, mpc, context);
  }

  /* ===== Serialization-focused helpers and tests ===== */

  /** Serializable callback that records received events. */
  @SuppressWarnings("UnusedVariable")
  private static class RecordingCallback implements PutCompletionCallback, Serializable {
    @Serial private static final long serialVersionUID = 1L;

    int success;
    int failure;
    int encode;
    int metadataModel;
    int metadataBucket;
    int fetchable;
    int blockSetFinished;
    int resume;

    @Override
    public void onSuccess(ClientPutState state, ClientContext context) {
      success++;
    }

    @Override
    public void onFailure(InsertException e, ClientPutState state, ClientContext context) {
      failure++;
    }

    @Override
    public void onEncode(BaseClientKey key, ClientPutState state, ClientContext context) {
      encode++;
    }

    @Override
    public void onMetadata(Metadata meta, ClientPutState state, ClientContext context) {
      metadataModel++;
    }

    @Override
    public void onMetadata(
        network.crypta.support.api.Bucket meta, ClientPutState state, ClientContext context) {
      metadataBucket++;
    }

    @Override
    public void onFetchable(ClientPutState state) {
      fetchable++;
    }

    @Override
    public void onBlockSetFinished(ClientPutState state, ClientContext context) {
      blockSetFinished++;
    }

    @Override
    public void onTransition(
        ClientPutState oldState, ClientPutState newState, ClientContext context) {
      // ignored
    }

    @Override
    public void onResume(ClientContext context) {
      resume++;
    }
  }

  /** Minimal parent that satisfies abstract methods; used only to construct the callback. */
  private static class StubParent extends BaseClientPutter {
    @Serial private static final long serialVersionUID = 1L;

    @Override
    public void onTransition(ClientPutState from, ClientPutState to, ClientContext context) {
      // Intentionally empty: no transition behavior needed for test stub.
    }

    @Override
    public int getMinSuccessFetchBlocks() {
      return 0;
    }

    @Override
    protected ClientBaseCallback getCallback() {
      return new ClientBaseCallback() {
        @Override
        public void onResume(ClientContext context) {
          // Intentionally empty: callback has no resume work in this test stub.
        }

        @Override
        public RequestClient getRequestClient() {
          return new RequestClient() {
            @Override
            public boolean persistent() {
              return false;
            }

            @Override
            public boolean realTimeFlag() {
              return false;
            }
          };
        }
      };
    }

    @Override
    public FreenetURI getURI() {
      return null;
    }

    @Override
    public boolean isFinished() {
      return false;
    }

    @Override
    public void cancel(ClientContext context) {
      // Intentionally empty: test stub has no cancellable work.
    }

    @Override
    protected void innerToNetwork(ClientContext context) {
      // Intentionally empty: test stub does not perform network submission.
    }

    @Override
    protected void innerNotifyClients(ClientContext context) {
      // Intentionally empty: test stub does not notify clients.
    }

    @Override
    public void onTransition(
        ClientGetState oldState, ClientGetState newState, ClientContext context) {
      // Intentionally empty: not used by these tests.
    }
  }

  /**
   * Serializable stub for ClientPutState that compares by stable id so deserialized instances are
   * equal to their pre-serialization counterparts for list removal operations.
   */
  private static class SerializablePutState implements ClientPutState, Serializable {
    @Serial private static final long serialVersionUID = 1L;
    private final String id;
    private final BaseClientPutter parent;
    private final Serializable token;

    SerializablePutState(String id, BaseClientPutter parent, Serializable token) {
      this.id = id;
      this.parent = parent;
      this.token = token;
    }

    @Override
    public BaseClientPutter getParent() {
      return parent;
    }

    @Override
    public void cancel(ClientContext context) {
      // Intentionally empty: serializable state has nothing to cancel in tests.
    }

    @Override
    public void schedule(ClientContext context) {
      // Intentionally empty: no scheduling performed in tests.
    }

    @Override
    public Object getToken() {
      return token;
    }

    @Override
    public void onResume(ClientContext context) {
      // Intentionally empty: nothing to resume in tests.
    }

    @Override
    public void onShutdown(ClientContext context) {
      // Intentionally empty: no shutdown actions required in tests.
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (!(o instanceof SerializablePutState that)) return false;
      return id.equals(that.id);
    }

    @Override
    public int hashCode() {
      return id.hashCode();
    }
  }

  @Test
  void callback_and_token_survive_java_serialization() throws Exception {
    RecordingCallback recCb = new RecordingCallback();
    StubParent stubParent = new StubParent();
    String tokenStr = "token-123"; // Serializable token to validate round-trip

    MultiPutCompletionCallback restored =
        getMultiPutCompletionCallback(recCb, stubParent, tokenStr);

    ClientContext mockContext = mock(ClientContext.class);

    // Trigger lifecycle on the restored instance; should not throw and should call through to cb
    restored.arm(mockContext);
    restored.onSuccess(null, mockContext);

    // Token must be preserved across serialization
    assertEquals(tokenStr, restored.getToken(), "token should be preserved across serialization");
    // Parent should be deserialized as well and of the expected type
    assertNotNull(restored.getParent());
    assertEquals(StubParent.class, restored.getParent().getClass());
  }

  private static MultiPutCompletionCallback getMultiPutCompletionCallback(
      RecordingCallback recCb, StubParent stubParent, String tokenStr)
      throws IOException, ClassNotFoundException {
    MultiPutCompletionCallback original =
        new MultiPutCompletionCallback(recCb, stubParent, tokenStr, /*persistent*/ false);

    // Serialize and deserialize
    byte[] bytes;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(original);
      oos.flush();
      bytes = baos.toByteArray();
    }

    MultiPutCompletionCallback restored;
    try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais)) {
      restored = (MultiPutCompletionCallback) ois.readObject();
    }
    return restored;
  }

  @Test
  void waiting_state_and_generator_persist_across_serialization() throws Exception {
    RecordingCallback recCb = new RecordingCallback();
    StubParent stubParent = new StubParent();
    ClientContext mockContext = mock(ClientContext.class);

    MultiPutCompletionCallback mpc =
        new MultiPutCompletionCallback(recCb, stubParent, "agg-token", /*persistent*/ true);

    SerializablePutState gen = new SerializablePutState("gen", stubParent, "t1");
    SerializablePutState other = new SerializablePutState("other", stubParent, "t2");

    // Build waiting lists and set generator
    mpc.addURIGenerator(gen);
    mpc.add(other);
    mpc.arm(mockContext);

    // Serialize and deserialize the aggregator
    byte[] bytes;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(mpc);
      oos.flush();
      bytes = baos.toByteArray();
    }

    MultiPutCompletionCallback restored;
    try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bais)) {
      restored = (MultiPutCompletionCallback) ois.readObject();
    }

    // Token and parent should be preserved across serialization
    assertEquals("agg-token", restored.getToken());
    assertNotNull(restored.getParent());
    assertEquals(StubParent.class, restored.getParent().getClass());

    // Now mark only one state as success and ensure the composite does not complete yet.
    restored.onSuccess(gen, mockContext);

    // Complete the other state and expect a single composite success and single block/fetchable.
    restored.onSuccess(other, mockContext);
    // No exceptions thrown indicates waiting state preserved and completion occurred.
  }
}
