package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.io.InputStream;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Test method naming convention: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class RealArchiveStoreItemTest {

  @Mock private ArchiveStoreContext mockContext;

  @Test
  @DisplayName("constructor: null bucket -> NullPointerException")
  void constructor_whenNullBucket_expectNullPointerException() {
    FreenetURI key = new FreenetURI("KSK", "doc");
    assertThrows(
        NullPointerException.class,
        () -> new RealArchiveStoreItem(mockContext, key, "file.txt", null));
  }

  @Test
  @DisplayName("dataAsBucket: returns same read-only reader with expected size/content")
  void dataAsBucket_whenConstructed_expectReadOnlySameSizeAndIdentity() throws Exception {
    byte[] data = "hello".getBytes();
    ArrayBucket underlying = new ArrayBucket(data);
    FreenetURI key = new FreenetURI("KSK", "doc");

    RealArchiveStoreItem item = new RealArchiveStoreItem(mockContext, key, "file.txt", underlying);

    Bucket first = item.dataAsBucket();
    Bucket second = item.dataAsBucket();

    assertSame(first, second, "dataAsBucket should return the same reader instance");
    assertEquals(data.length, first.size(), "reader size should match initial data length");
    // ReaderBucket reports read-only behavior
    // getOutputStream methods should throw IOException, but isReadOnly() should be true.
    // MultiReaderBucket.ReaderBucket#isReadOnly() returns true.
    // We do not attempt to write via the reader; just assert read-only view is advertised.
    // There is no dedicated getter, but trying to open an output stream should fail.
    assertThrows(IOException.class, first::getOutputStream);
    // Validate content is readable
    try (InputStream in = first.getInputStream()) {
      byte[] got = in.readAllBytes();
      assertArrayEquals(data, got, "reader must expose the original bytes");
    }
  }

  @Test
  @DisplayName(
      "dataSize/spaceUsed: spaceUsed is captured at construction; dataSize reflects live underlying"
          + " size")
  void dataSize_whenUnderlyingMutates_expectSpaceUsedStaysInitial() throws Exception {
    byte[] initial = "abc".getBytes(); // 3 bytes
    ArrayBucket underlying = new ArrayBucket(initial);
    FreenetURI key = new FreenetURI("KSK", "doc");
    RealArchiveStoreItem item = new RealArchiveStoreItem(mockContext, key, "file.bin", underlying);

    assertEquals(3L, item.spaceUsed(), "spaceUsed should capture initial size");
    assertEquals(3L, item.dataSize(), "dataSize initially equals underlying size");

    // Mutate the underlying ArrayBucket directly (MultiReaderBucket does not set it read-only).
    java.io.OutputStream os = underlying.getOutputStream();
    os.write("abcdef".getBytes()); // now 6 bytes
    os.close();

    assertEquals(6L, item.dataSize(), "dataSize should reflect updated underlying size");
    assertEquals(3L, item.spaceUsed(), "spaceUsed must remain the initially captured value");
  }

  @Test
  @DisplayName("getReaderBucket: returns independent reader; still open while main reader is alive")
  void getReaderBucket_whenOpen_expectIndependentReadableReader() throws Exception {
    byte[] data = "012345".getBytes();
    ArrayBucket underlying = new ArrayBucket(data);
    FreenetURI key = new FreenetURI("KSK", "doc");
    RealArchiveStoreItem item = new RealArchiveStoreItem(mockContext, key, "entry", underlying);

    Bucket main = item.dataAsBucket();
    Bucket r1 = item.getReaderBucket();
    assertNotNull(r1, "first reader bucket should be available");
    assertNotSame(main, r1, "reader returned by getReaderBucket must be distinct from main");

    try (InputStream in = r1.getInputStream()) {
      byte[] got = in.readAllBytes();
      assertArrayEquals(data, got, "reader must expose the underlying bytes");
    }

    // Free r1; underlying must remain alive as main reader is still held by the item.
    r1.free();
    // Request another reader; still available because main reader has not been freed.
    Bucket r2 = item.getReaderBucket();
    assertNotNull(r2, "subsequent reader should still be available before item is closed");
    r2.free();
  }

  @Test
  @DisplayName(
      "innerClose: frees main reader; subsequent getReaderBucket returns null; main reader becomes"
          + " unusable")
  void innerClose_whenCalled_expectReadersClosed() {
    byte[] data = "xyz".getBytes();
    ArrayBucket underlying = new ArrayBucket(data);
    FreenetURI key = new FreenetURI("KSK", "doc");
    RealArchiveStoreItem item = new RealArchiveStoreItem(mockContext, key, "x", underlying);

    // Close the item (directly call innerClose for a focused check)
    item.innerClose();

    // Further readers cannot be obtained
    assertNull(item.getReaderBucket(), "no new readers after close");

    // The main reader is the one returned by dataAsBucket(); it should now be unusable.
    Bucket main = item.dataAsBucket();
    assertThrows(IOException.class, main::getInputStream, "main reader should be freed");
  }

  @Test
  @DisplayName("innerClose: idempotent; underlying freed only once")
  void innerClose_whenCalledTwice_expectUnderlyingFreedOnce() {
    byte[] data = "payload".getBytes();
    ArrayBucket underlyingReal = new ArrayBucket(data);
    ArrayBucket underlyingSpy = spy(underlyingReal);
    FreenetURI key = new FreenetURI("KSK", "doc");
    RealArchiveStoreItem item = new RealArchiveStoreItem(mockContext, key, "f", underlyingSpy);

    // Underlying not freed yet
    verify(underlyingSpy, never()).free();

    item.innerClose();
    item.innerClose(); // idempotent on the reader; underlying free should still be once

    verify(underlyingSpy, times(1)).free();
  }

  @Test
  @DisplayName("close: delegates to context.removeItem(this)")
  void close_whenCalled_expectContextRemoveItemInvoked() {
    byte[] data = {1, 2, 3};
    ArrayBucket underlying = new ArrayBucket(data);
    FreenetURI key = new FreenetURI("KSK", "doc");
    RealArchiveStoreItem item = new RealArchiveStoreItem(mockContext, key, "file", underlying);

    item.close(); // base class method

    verify(mockContext).removeItem(item);
  }

  @Test
  @DisplayName("close via real context: removing triggers cleanup and frees underlying once")
  void close_whenRegisteredWithRealContext_expectUnderlyingFreedOnceAndNoFurtherReaders() {
    byte[] data = "abcdef".getBytes();
    ArrayBucket underlyingReal = new ArrayBucket(data);
    ArrayBucket underlyingSpy = spy(underlyingReal);
    FreenetURI key = new FreenetURI("KSK", "doc");
    ArchiveStoreContext realCtx = new ArchiveStoreContext(key, ArchiveManager.ARCHIVE_TYPE.ZIP);
    RealArchiveStoreItem item = new RealArchiveStoreItem(realCtx, key, "entry.txt", underlyingSpy);

    // Register then close through the public API so ArchiveStoreContext invokes innerClose()
    item.addToContext();
    item.close();
    item.close(); // second close is a no-op in context; should not double-free

    verify(underlyingSpy, times(1)).free();
    assertNull(item.getReaderBucket(), "wrapper should be closed after item cleanup");
  }

  @Test
  @DisplayName("getDataOrThrow: returns the same instance as dataAsBucket()")
  void getDataOrThrow_whenCalled_expectSameAsDataAsBucket() {
    ArrayBucket underlying = new ArrayBucket("v".getBytes());
    FreenetURI key = new FreenetURI("KSK", "doc");
    RealArchiveStoreItem item = new RealArchiveStoreItem(mockContext, key, "n", underlying);

    Bucket b1 = item.dataAsBucket();
    Bucket b2 = item.getDataOrThrow();
    assertSame(b1, b2, "getDataOrThrow should return the main reader bucket");
  }
}
