package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextResources;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatchers;
import org.mockito.InOrder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DelayedFreeRandomAccessBucketTest {

  private PersistentFileTracker factory;
  private RandomAccessBucket underlying;

  @BeforeEach
  void setup() {
    factory = mock(PersistentFileTracker.class);
    when(factory.commitID()).thenReturn(101L);
    underlying = mock(RandomAccessBucket.class);
  }

  @Test
  void constructor_whenBucketIsNull_expectNPE() {
    assertThrows(
        NullPointerException.class,
        () -> {
          try (var _ = new DelayedFreeRandomAccessBucket(factory, null)) {
            fail("unreachable");
          }
        });
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void constructor_whenFactoryIsNull_expectNPE() {
    // NPE occurs when reading commitID() on null factory
    assertThrows(
        NullPointerException.class,
        () -> {
          try (var _ = new DelayedFreeRandomAccessBucket(null, underlying)) {
            fail("unreachable");
          }
        });
  }

  @Test
  void getUnderlying_whenFreed_returnsNull() {
    // Arrange
    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);

    // Act: before free
    assertSame(underlying, bucket.getUnderlying());

    // Act: free
    bucket.free();

    // Assert
    assertNull(bucket.getUnderlying());
  }

  @Test
  void free_whenCalledTwice_idempotent() {
    // Arrange
    when(factory.commitID()).thenReturn(777L); // commit captured at construction
    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);

    // Act
    bucket.free();
    bucket.free();

    // Assert
    assertTrue(bucket.toFree());
    verify(factory, times(1)).delayedFree(bucket, 777L);
  }

  @Test
  void free_whenResumed_usesNewFactoryButOriginalCommitID() throws ResumeFailedException {
    // Arrange: factory at creation time (commit captured)
    PersistentFileTracker factoryAtCreate = mock(PersistentFileTracker.class);
    when(factoryAtCreate.commitID()).thenReturn(42L);
    DelayedFreeRandomAccessBucket bucket =
        new DelayedFreeRandomAccessBucket(factoryAtCreate, underlying);

    // Underlying should receive onResume()
    doNothing().when(underlying).onResume(any());

    // New factory after resume
    PersistentTempBucketFactory newFactory = mock(PersistentTempBucketFactory.class);

    // Build a minimal ClientContext with the new factory; other args can be mocks/nulls where safe
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
                newFactory,
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

    // Act: resume then free
    bucket.onResume(ctx);
    bucket.free();

    // Assert: delayedFree invoked on the NEW factory with the ORIGINAL commit id
    verify(newFactory, times(1)).delayedFree(bucket, 42L);
    verify(factoryAtCreate, never()).delayedFree(any(), anyLong());
    verify(underlying, times(1)).onResume(ctx);
  }

  static StreamAction[] streamActions() {
    return new StreamAction[] {
      new StreamAction(
          "getOutputStream",
          (w, u) -> {
            OutputStream os = new ByteArrayOutputStream();
            when(u.getOutputStream()).thenReturn(os);
            return w.getOutputStream();
          }),
      new StreamAction(
          "getOutputStreamUnbuffered",
          (w, u) -> {
            OutputStream os = new ByteArrayOutputStream();
            when(u.getOutputStreamUnbuffered()).thenReturn(os);
            return w.getOutputStreamUnbuffered();
          }),
      new StreamAction(
          "getInputStream",
          (w, u) -> {
            InputStream is = new ByteArrayInputStream(new byte[0]);
            when(u.getInputStream()).thenReturn(is);
            return w.getInputStream();
          }),
      new StreamAction(
          "getInputStreamUnbuffered",
          (w, u) -> {
            InputStream is = new ByteArrayInputStream(new byte[0]);
            when(u.getInputStreamUnbuffered()).thenReturn(is);
            return w.getInputStreamUnbuffered();
          })
    };
  }

  @ParameterizedTest(name = "{0} when freed throws IOException")
  @MethodSource("streamActions")
  void ioMethods_whenFreed_expectIOException(StreamAction action) {
    // Arrange
    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);
    bucket.free();

    // Act + Assert
    IOException ex = assertThrows(IOException.class, () -> action.invoke(bucket, underlying));
    assertThat(ex.getMessage(), containsString("Already freed"));
  }

  @ParameterizedTest(name = "{0} delegates to underlying when not freed")
  @MethodSource("streamActions")
  void ioMethods_whenNotFreed_delegate(StreamAction action) throws IOException {
    // Arrange
    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);

    // Act
    Closeable stream = action.invoke(bucket, underlying);

    // Assert
    assertNotNull(stream);
  }

  @Test
  void toRandomAccessBuffer_whenNotFreed_wrapsAndSetsReadOnly() throws IOException {
    // Arrange
    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    when(underlying.toRandomAccessBuffer()).thenReturn(raf);

    // Act
    LockableRandomAccessBuffer out = bucket.toRandomAccessBuffer();

    // Assert
    assertNotNull(out);
    assertThat(out, instanceOf(DelayedFreeRandomAccessBuffer.class));
    InOrder order = inOrder(underlying);
    order.verify(underlying, times(1)).setReadOnly();
    order.verify(underlying, times(1)).toRandomAccessBuffer();
  }

  @Test
  void toRandomAccessBuffer_whenFreed_expectIOException() {
    // Arrange
    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);
    bucket.free();

    // Act + Assert
    assertThrows(IOException.class, bucket::toRandomAccessBuffer);
  }

  @Test
  void basicDelegations_whenCalled_delegateToUnderlying() {
    // Arrange
    when(underlying.getName()).thenReturn("n");
    when(underlying.size()).thenReturn(0L, 123L);
    when(underlying.isReadOnly()).thenReturn(false, true);
    RandomAccessBucket shadow = mock(RandomAccessBucket.class);
    when(underlying.createShadow()).thenReturn(shadow);

    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);

    // Act + Assert
    assertEquals("n", bucket.getName());
    assertEquals(0L, bucket.size());
    assertFalse(bucket.isReadOnly());

    bucket.setReadOnly();
    verify(underlying, times(1)).setReadOnly();

    assertTrue(bucket.isReadOnly());
    assertSame(shadow, bucket.createShadow());

    bucket.realFree();
    verify(underlying, times(1)).free();
  }

  @Test
  void storeTo_whenCalled_writesHeaderAndDelegates() throws IOException {
    // Arrange
    DelayedFreeRandomAccessBucket bucket = new DelayedFreeRandomAccessBucket(factory, underlying);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);

    // Act
    bucket.storeTo(dos);
    dos.flush();

    // Assert bytes
    byte[] data = baos.toByteArray();
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
      assertEquals(DelayedFreeRandomAccessBucket.MAGIC, dis.readInt());
      assertEquals(DelayedFreeRandomAccessBucket.VERSION, dis.readInt());
    }
    verify(underlying, times(1)).storeTo(ArgumentMatchers.any(DataOutputStream.class));
  }

  // Helper types for parameterized stream tests
  private interface IOSupplier {
    Closeable get(DelayedFreeRandomAccessBucket wrapper, RandomAccessBucket underlying)
        throws IOException;
  }

  private record StreamAction(String name, IOSupplier supplier)
      implements Comparable<StreamAction> {

    Closeable invoke(DelayedFreeRandomAccessBucket wrapper, RandomAccessBucket underlying)
        throws IOException {
      return supplier.get(wrapper, underlying);
    }

    @Override
    public @NotNull String toString() {
      return name;
    }

    @Override
    public int compareTo(StreamAction o) {
      return this.name.compareTo(o.name);
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (!(obj instanceof StreamAction other)) {
        return false;
      }
      return name.equals(other.name);
    }

    @Override
    public int hashCode() {
      return name.hashCode();
    }
  }
}
