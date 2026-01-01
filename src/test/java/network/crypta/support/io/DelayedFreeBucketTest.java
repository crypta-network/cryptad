package network.crypta.support.io;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.*;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unit tests for {@link DelayedFreeBucket}.
 *
 * <p>Tests follow AAA style and mock external I/O with Mockito.
 */
class DelayedFreeBucketTest {

  private static DelayedFreeBucket newSut(PersistentFileTracker tracker, Bucket underlying) {
    return new DelayedFreeBucket(tracker, underlying);
  }

  @Test
  @DisplayName("constructor_nullBucket_throwsNPE")
  void constructor_nullBucket_throwsNPE() {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    assertThrows(
        NullPointerException.class,
        () -> {
          try (var _ = new DelayedFreeBucket(pft, null)) {
            fail("constructor should have thrown before entering try block");
          }
        });
  }

  @Test
  @DisplayName("toFree_initiallyFalse_thenTrueAfterFree")
  void toFree_initiallyFalse_thenTrueAfterFree() {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    when(pft.commitID()).thenReturn(123L);
    Bucket underlying = mock(Bucket.class);

    DelayedFreeBucket sut = newSut(pft, underlying);
    assertFalse(sut.toFree());

    sut.free();
    assertTrue(sut.toFree());
  }

  @Test
  @DisplayName("getUnderlying_beforeFreeAndMigration_returnsUnderlying")
  void getUnderlying_beforeFreeAndMigration_returnsUnderlying() {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    Bucket underlying = mock(Bucket.class);
    DelayedFreeBucket sut = newSut(pft, underlying);
    assertSame(underlying, sut.getUnderlying());
  }

  @Test
  @DisplayName("getUnderlying_afterFree_returnsNull")
  void getUnderlying_afterFree_returnsNull() {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    when(pft.commitID()).thenReturn(1L);
    Bucket underlying = mock(Bucket.class);
    DelayedFreeBucket sut = newSut(pft, underlying);
    sut.free();
    assertNull(sut.getUnderlying());
  }

  @Test
  @DisplayName("getUnderlying_afterMigration_returnsNull")
  void getUnderlying_afterMigration_returnsNull() throws IOException {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    RandomAccessBucket rab = mock(RandomAccessBucket.class);
    DelayedFreeBucket sut = newSut(pft, rab);
    assertNotNull(sut.toRandomAccessBucket());
    assertNull(sut.getUnderlying());
  }

  // Parameter set: method names of the four stream getters
  private static Stream<String> streamGetters() {
    return Stream.of(
        "getOutputStream",
        "getOutputStreamUnbuffered",
        "getInputStream",
        "getInputStreamUnbuffered");
  }

  @ParameterizedTest(name = "{0}_whenNotFreedOrMigrated_delegates")
  @MethodSource("streamGetters")
  void streamGetter_whenNotFreedOrMigrated_delegates(String name) throws Exception {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    Bucket b = mock(Bucket.class);
    when(b.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(b.getOutputStreamUnbuffered()).thenReturn(new ByteArrayOutputStream());
    when(b.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(b.getInputStreamUnbuffered()).thenReturn(new ByteArrayInputStream(new byte[0]));
    DelayedFreeBucket sut = newSut(pft, b);

    // Act & Assert: no exception and not null
    switch (name) {
      case "getOutputStream" -> assertNotNull(sut.getOutputStream());
      case "getOutputStreamUnbuffered" -> assertNotNull(sut.getOutputStreamUnbuffered());
      case "getInputStream" -> assertNotNull(sut.getInputStream());
      case "getInputStreamUnbuffered" -> assertNotNull(sut.getInputStreamUnbuffered());
      default -> fail("unexpected parameter: " + name);
    }
  }

  @ParameterizedTest(name = "{0}_whenFreed_throwsIOException")
  @MethodSource("streamGetters")
  void streamGetter_whenFreed_throwsIOException(String name) throws Exception {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    when(pft.commitID()).thenReturn(77L);
    Bucket b = mock(Bucket.class);
    when(b.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(b.getOutputStreamUnbuffered()).thenReturn(new ByteArrayOutputStream());
    when(b.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(b.getInputStreamUnbuffered()).thenReturn(new ByteArrayInputStream(new byte[0]));
    DelayedFreeBucket sut = newSut(pft, b);
    sut.free();

    IOException ex;
    switch (name) {
      case "getOutputStream" -> ex = assertThrows(IOException.class, sut::getOutputStream);
      case "getOutputStreamUnbuffered" ->
          ex = assertThrows(IOException.class, sut::getOutputStreamUnbuffered);
      case "getInputStream" -> ex = assertThrows(IOException.class, sut::getInputStream);
      case "getInputStreamUnbuffered" ->
          ex = assertThrows(IOException.class, sut::getInputStreamUnbuffered);
      default -> throw new AssertionError("unexpected parameter: " + name);
    }
    assertThat(ex.getMessage(), containsString("Already freed"));
  }

  @ParameterizedTest(name = "{0}_whenMigrated_throwsIOException")
  @MethodSource("streamGetters")
  void streamGetter_whenMigrated_throwsIOException(String name) throws Exception {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    RandomAccessBucket rab = mock(RandomAccessBucket.class);
    when(rab.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(rab.getInputStreamUnbuffered()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(rab.getOutputStream()).thenReturn(new ByteArrayOutputStream());
    when(rab.getOutputStreamUnbuffered()).thenReturn(new ByteArrayOutputStream());
    DelayedFreeBucket sut = newSut(pft, rab);
    assertNotNull(sut.toRandomAccessBucket()); // triggers migrated=true

    IOException ex;
    switch (name) {
      case "getOutputStream" -> ex = assertThrows(IOException.class, sut::getOutputStream);
      case "getOutputStreamUnbuffered" ->
          ex = assertThrows(IOException.class, sut::getOutputStreamUnbuffered);
      case "getInputStream" -> ex = assertThrows(IOException.class, sut::getInputStream);
      case "getInputStreamUnbuffered" ->
          ex = assertThrows(IOException.class, sut::getInputStreamUnbuffered);
      default -> throw new AssertionError("unexpected parameter: " + name);
    }
    assertThat(ex.getMessage(), containsString("Already migrated to a RandomAccessBucket"));
  }

  @Test
  @DisplayName("free_whenCalled_callsDelayedFreeOnceWithCreatedCommitID")
  void free_whenCalled_callsDelayedFreeOnceWithCreatedCommitID() {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    when(pft.commitID()).thenReturn(42L);
    Bucket underlying = mock(Bucket.class);
    DelayedFreeBucket sut = newSut(pft, underlying);

    sut.free();
    sut.free(); // idempotent; still exactly one call

    verify(pft, times(1)).delayedFree(sut, 42L);
  }

  @Test
  @DisplayName("free_afterMigration_noopDoesNotCallFactory")
  void free_afterMigration_noopDoesNotCallFactory() throws IOException {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    RandomAccessBucket rab = mock(RandomAccessBucket.class);
    DelayedFreeBucket sut = newSut(pft, rab);
    assertNotNull(sut.toRandomAccessBucket());
    sut.free();
    verify(pft, never()).delayedFree(any(), anyLong());
  }

  @Test
  @DisplayName("toRandomAccessBucket_whenUnderlyingNotRAB_returnsNull")
  void toRandomAccessBucket_whenUnderlyingNotRAB_returnsNull() throws IOException {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    Bucket plain = mock(Bucket.class);
    DelayedFreeBucket sut = newSut(pft, plain);
    assertNull(sut.toRandomAccessBucket());
    // Still usable after null return
    when(plain.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    assertNotNull(sut.getInputStream());
  }

  @Test
  @DisplayName("toRandomAccessBucket_whenFreed_thenThrows")
  void toRandomAccessBucket_whenFreed_thenThrows() {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    when(pft.commitID()).thenReturn(33L);
    Bucket underlying = mock(Bucket.class);
    DelayedFreeBucket sut = newSut(pft, underlying);
    sut.free();
    assertThrows(IOException.class, sut::toRandomAccessBucket);
  }

  @Test
  @DisplayName("toRandomAccessBucket_whenUnderlyingIsRAB_returnsWrapperAndBlocksStreams")
  void toRandomAccessBucket_whenUnderlyingIsRAB_returnsWrapperAndBlocksStreams() throws Exception {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    RandomAccessBucket rab = mock(RandomAccessBucket.class);
    DelayedFreeBucket sut = newSut(pft, rab);

    Bucket wrapped = sut.toRandomAccessBucket();
    assertNotNull(wrapped);
    assertInstanceOf(DelayedFreeRandomAccessBucket.class, wrapped);

    IOException ex = assertThrows(IOException.class, sut::getInputStream);
    assertThat(ex.getMessage(), containsString("Already migrated"));

    // Free after migration: no call to delayedFree
    sut.free();
    verify(pft, never()).delayedFree(any(), anyLong());
  }

  @Test
  @DisplayName("onResume_whenCalled_delegatesToUnderlying")
  void onResume_whenCalled_delegatesToUnderlying() throws ResumeFailedException {
    PersistentFileTracker original = mock(PersistentFileTracker.class);
    Bucket underlying = mock(Bucket.class);
    DelayedFreeBucket sut = newSut(original, underlying);
    ClientContext ctx = mock(ClientContext.class);
    // Act
    sut.onResume(ctx);
    // Assert
    verify(underlying, times(1)).onResume(ctx);
  }

  @Test
  @DisplayName("free_afterFactorySwap_usesOriginalCreatedCommitID")
  void free_afterFactorySwap_usesOriginalCreatedCommitID() throws Exception {
    // Arrange original factory (commitID captured at construction)
    PersistentFileTracker original = mock(PersistentFileTracker.class);
    when(original.commitID()).thenReturn(11L);
    Bucket underlying = mock(Bucket.class);
    DelayedFreeBucket sut = newSut(original, underlying);

    // Swap the factory field to a new instance via reflection (simulates onResume wiring)
    PersistentTempBucketFactory newFactory = mock(PersistentTempBucketFactory.class);
    var field = DelayedFreeBucket.class.getDeclaredField("factory");
    field.setAccessible(true);
    field.set(sut, newFactory);

    // Act
    sut.free();

    // Assert: delayedFree called on the new factory with the original createdCommitID (11)
    verify(newFactory, times(1)).delayedFree(sut, 11L);
    verify(original, never()).delayedFree(any(), anyLong());
  }

  @Test
  @DisplayName("storeTo_writesMagicVersionThenDelegates")
  void storeTo_writesMagicVersionThenDelegates() throws Exception {
    PersistentFileTracker pft = mock(PersistentFileTracker.class);
    Bucket underlying = mock(Bucket.class);

    // Make underlying write a known marker so we can assert ordering
    doAnswer(
            inv -> {
              DataOutputStream dos = inv.getArgument(0);
              dos.writeInt(0xCAFEBABE);
              return null;
            })
        .when(underlying)
        .storeTo(org.mockito.ArgumentMatchers.any(DataOutputStream.class));

    DelayedFreeBucket sut = newSut(pft, underlying);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);

    sut.storeTo(dos);
    dos.flush();

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    assertEquals(DelayedFreeBucket.MAGIC, dis.readInt());
    assertEquals(1, dis.readInt());
    assertEquals(0xCAFEBABE, dis.readInt());
    verify(underlying, times(1)).storeTo(org.mockito.ArgumentMatchers.any(DataOutputStream.class));
  }

  @Nested
  class DelegationTests {
    @Test
    @DisplayName("createShadow_delegates")
    void createShadow_delegates() {
      PersistentFileTracker pft = mock(PersistentFileTracker.class);
      Bucket underlying = mock(Bucket.class);
      Bucket shadow = mock(Bucket.class);
      when(underlying.createShadow()).thenReturn(shadow);
      DelayedFreeBucket sut = newSut(pft, underlying);
      assertSame(shadow, sut.createShadow());
    }

    @Test
    @DisplayName("realFree_delegatesToBucketFree")
    void realFree_delegatesToBucketFree() {
      PersistentFileTracker pft = mock(PersistentFileTracker.class);
      Bucket underlying = mock(Bucket.class);
      DelayedFreeBucket sut = newSut(pft, underlying);
      sut.realFree();
      verify(underlying, times(1)).free();
    }

    @Test
    @DisplayName("nameSizeReadOnly_delegates")
    void nameSizeReadOnly_delegates() {
      PersistentFileTracker pft = mock(PersistentFileTracker.class);
      Bucket underlying = mock(Bucket.class);
      when(underlying.getName()).thenReturn("test-bucket");
      when(underlying.size()).thenReturn(123L);
      when(underlying.isReadOnly()).thenReturn(false).thenReturn(true);
      DelayedFreeBucket sut = newSut(pft, underlying);

      assertEquals("test-bucket", sut.getName());
      assertEquals(123L, sut.size());
      assertFalse(sut.isReadOnly());
      sut.setReadOnly();
      verify(underlying, times(1)).setReadOnly();
      assertTrue(sut.isReadOnly());
    }
  }
}
