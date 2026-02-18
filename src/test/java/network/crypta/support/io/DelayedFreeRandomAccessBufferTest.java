package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.crypt.MasterSecret;
import network.crypta.node.ClientContextResources;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DelayedFreeRandomAccessBufferTest {

  private PersistentFileTracker factory;
  private LockableRandomAccessBuffer underlying;

  @BeforeEach
  void setup() {
    factory = mock(PersistentFileTracker.class);
    when(factory.commitID()).thenReturn(101L);
    underlying = mock(LockableRandomAccessBuffer.class);
  }

  @Test
  void toFree_whenInitiallyFalse_afterFreeTrue() {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    assertFalse(buf.toFree());
    buf.free();
    assertTrue(buf.toFree());
  }

  @Test
  void free_whenCalledTwice_idempotent() {
    when(factory.commitID()).thenReturn(777L);
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);

    buf.free();
    buf.free();

    assertTrue(buf.toFree());
    verify(factory, times(1)).delayedFree(buf, 777L);
  }

  @Test
  void free_whenResumed_usesNewFactoryButOriginalCommitID() throws ResumeFailedException {
    PersistentFileTracker factoryAtCreate = mock(PersistentFileTracker.class);
    when(factoryAtCreate.commitID()).thenReturn(42L);
    DelayedFreeRandomAccessBuffer buf =
        new DelayedFreeRandomAccessBuffer(underlying, factoryAtCreate);

    doNothing().when(underlying).onResume(any());

    PersistentTempBucketFactory newFactory = mock(PersistentTempBucketFactory.class);
    Random fastWeak = mock(Random.class);
    ClientContext ctx =
        new ClientContext(
            1L,
            new ClientContextRuntime(
                mock(network.crypta.client.async.ClientLayerPersister.class),
                mock(PriorityAwareExecutor.class),
                mock(network.crypta.support.MemoryLimitedJobRunner.class),
                mock(network.crypta.support.Ticker.class),
                mock(network.crypta.crypt.RandomSource.class),
                fastWeak,
                mock(MasterSecret.class)),
            new ClientContextStorageFactories(
                newFactory,
                mock(TempBucketFactory.class),
                mock(PersistentFileTracker.class),
                mock(FilenameGenerator.class),
                mock(FilenameGenerator.class),
                mock(network.crypta.support.io.FileRandomAccessBufferFactory.class),
                mock(network.crypta.support.io.FileRandomAccessBufferFactory.class)),
            new ClientContextRafFactories(
                mock(network.crypta.support.api.LockableRandomAccessBufferFactory.class),
                mock(network.crypta.support.api.LockableRandomAccessBufferFactory.class)),
            new ClientContextServices(
                new ClientContextResources(
                    mock(network.crypta.client.ArchiveManager.class),
                    mock(network.crypta.client.async.HealingQueue.class)),
                mock(network.crypta.client.async.USKManager.class),
                mock(network.crypta.support.compress.RealCompressor.class),
                mock(network.crypta.client.async.DatastoreChecker.class),
                mock(network.crypta.clients.fcp.PersistentRequestRoot.class),
                mock(network.crypta.client.filter.LinkFilterExceptionProvider.class)),
            new ClientContextDefaults(
                mock(network.crypta.client.FetchContext.class),
                mock(network.crypta.client.InsertContext.class),
                mock(network.crypta.config.Config.class)));

    buf.onResume(ctx);
    buf.free();

    verify(newFactory, times(1)).delayedFree(buf, 42L);
    verify(factoryAtCreate, never()).delayedFree(any(), anyLong());
    verify(underlying, times(1)).onResume(ctx);
  }

  static OpAction[] freeGuardedOps() {
    return new OpAction[] {
      new OpAction(
          "pread",
          (b, u) -> {
            byte[] dst = new byte[8];
            b.pread(4L, dst, 1, 3);
          }),
      new OpAction(
          "pwrite",
          (b, u) -> {
            byte[] src = new byte[8];
            b.pwrite(6L, src, 2, 4);
          }),
      new OpAction("lockOpen", (b, u) -> b.lockOpen())
    };
  }

  @ParameterizedTest(name = "{0} when freed throws IOException")
  @MethodSource("freeGuardedOps")
  void ops_whenFreed_expectIOException(OpAction action) {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    buf.free();
    IOException ex = assertThrows(IOException.class, () -> action.run(buf, underlying));
    assertThat(ex.getMessage(), containsString("Already freed"));
  }

  @Test
  void pread_whenNotFreed_delegatesWithSameArgs() throws IOException {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    byte[] dst = new byte[16];

    buf.pread(5L, dst, 3, 7);

    verify(underlying, times(1)).pread(5L, dst, 3, 7);
  }

  @Test
  void pwrite_whenNotFreed_delegatesWithSameArgs() throws IOException {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    byte[] src = new byte[16];

    buf.pwrite(9L, src, 2, 6);

    verify(underlying, times(1)).pwrite(9L, src, 2, 6);
  }

  @Test
  void close_whenFreed_noDelegateClose() {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    buf.free();
    buf.close();
    verify(underlying, never()).close();
  }

  @Test
  void close_whenNotFreed_delegatesClose() {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    buf.close();
    verify(underlying, times(1)).close();
  }

  @Test
  void lockOpen_whenNotFreed_delegatesAndReturnsRafLock() throws IOException {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    RAFLock lock =
        new RAFLock() {
          @Override
          protected void innerUnlock() {
            // No-op for tests: we only need a concrete RAFLock instance.
          }
        };
    when(underlying.lockOpen()).thenReturn(lock);

    RAFLock out = buf.lockOpen();
    assertSame(lock, out);
    verify(underlying, times(1)).lockOpen();
  }

  @Test
  void size_whenCalled_delegates() {
    when(underlying.size()).thenReturn(123L);
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    assertEquals(123L, buf.size());
  }

  @Test
  void getUnderlying_whenFreed_returnsNull() {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    assertSame(underlying, buf.getUnderlying());
    buf.free();
    assertNull(buf.getUnderlying());
  }

  @Test
  void realFree_whenCalled_delegatesToUnderlying() {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    buf.realFree();
    verify(underlying, times(1)).free();
  }

  @Test
  void equalsAndHashCode_whenSameUnderlying_areEqual() {
    LockableRandomAccessBuffer same = underlying;
    DelayedFreeRandomAccessBuffer a = new DelayedFreeRandomAccessBuffer(same, factory);
    DelayedFreeRandomAccessBuffer b = new DelayedFreeRandomAccessBuffer(same, factory);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenDifferentUnderlying_notEqual() {
    LockableRandomAccessBuffer other = mock(LockableRandomAccessBuffer.class);
    DelayedFreeRandomAccessBuffer a = new DelayedFreeRandomAccessBuffer(underlying, factory);
    DelayedFreeRandomAccessBuffer b = new DelayedFreeRandomAccessBuffer(other, factory);
    assertNotEquals(b, a);
    assertNotEquals(null, a);
    assertNotEquals(new Object(), a);
  }

  @Test
  void storeTo_whenCalled_writesMagicAndDelegates() throws IOException {
    DelayedFreeRandomAccessBuffer buf = new DelayedFreeRandomAccessBuffer(underlying, factory);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);

    buf.storeTo(dos);
    dos.flush();

    byte[] data = baos.toByteArray();
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
      assertEquals(DelayedFreeRandomAccessBuffer.MAGIC, dis.readInt());
    }
    verify(underlying, times(1)).storeTo(org.mockito.ArgumentMatchers.any(DataOutputStream.class));
  }

  // Helper types for parameterized freed-guard tests
  private interface Op {
    void accept(DelayedFreeRandomAccessBuffer wrapper, LockableRandomAccessBuffer underlying)
        throws IOException;
  }

  private record OpAction(String name, Op op) {

    void run(DelayedFreeRandomAccessBuffer wrapper, LockableRandomAccessBuffer underlying)
        throws IOException {
      op.accept(wrapper, underlying);
    }

    @Override
    public @NotNull String toString() {
      return name;
    }
  }
}
