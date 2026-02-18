package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PaddedRandomAccessBucketTest {

  private static long expectedPaddedLength(long size) {
    final long MIN = 1024L;
    if (size <= MIN) return MIN;
    long max = MIN;
    while (max < size) {
      if (max < 0) throw new IllegalStateException("overflow while computing padded length");
      max <<= 1;
    }
    return max;
  }

  private static Stream<Arguments> sizes() {
    return Stream.of(
        Arguments.of(0L),
        Arguments.of(1L),
        Arguments.of(1023L),
        Arguments.of(1024L),
        Arguments.of(1025L),
        Arguments.of(2047L),
        Arguments.of(2048L),
        Arguments.of(4097L));
  }

  private static class InMemoryUnderlying {
    final RandomAccessBucket mock = mock(RandomAccessBucket.class);
    final ByteArrayOutputStream out = new ByteArrayOutputStream();

    InMemoryUnderlying() throws IOException {
      when(mock.getOutputStream()).thenReturn(out);
      when(mock.getOutputStreamUnbuffered()).thenReturn(out);
      // Return a fresh stream each time from current bytes
      when(mock.getInputStream()).thenAnswer(inv -> new ByteArrayInputStream(out.toByteArray()));
      when(mock.getInputStreamUnbuffered())
          .thenAnswer(inv -> new ByteArrayInputStream(out.toByteArray()));
      when(mock.getName()).thenReturn("Underlying");
      // Other methods are no-ops by default; verify via interactions where needed
    }
  }

  @ParameterizedTest(name = "size={0}")
  @MethodSource("sizes")
  void getOutputStream_whenWritingAndClosing_padsToExpectedLength(long size) throws IOException {
    InMemoryUnderlying u = new InMemoryUnderlying();
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(u.mock);

    OutputStream os = bucket.getOutputStream();
    // write deterministic pattern of the requested size
    byte[] data = new byte[(int) size];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);
    os.write(data);
    os.close();

    long expected = expectedPaddedLength(size);
    assertEquals(expected, u.out.size(), "underlying length must be padded");
    assertEquals(size, bucket.size(), "reported real size must equal bytes written");

    try (InputStream in = bucket.getInputStream()) {
      byte[] read = in.readNBytes((int) (size + 100));
      assertEquals((int) size, read.length, "reader must expose only real size");
      assertArrayEquals(Arrays.copyOf(data, read.length), read);
      assertEquals(-1, in.read(), "EOF expected after real size");
    }
  }

  @Test
  void getOutputStream_whenAlreadyOpen_throwsIOException() throws IOException {
    InMemoryUnderlying u = new InMemoryUnderlying();
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(u.mock);

    OutputStream first = bucket.getOutputStream();
    assertNotNull(first);
    IOException ex = assertThrows(IOException.class, bucket::getOutputStream);
    assertThat(ex.getMessage(), containsString("Already have an OutputStream"));
    first.close();
  }

  @Test
  void outputStream_writeAfterClose_throwsIOExceptionForArrayWrites() throws IOException {
    InMemoryUnderlying u = new InMemoryUnderlying();
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(u.mock);

    OutputStream os = bucket.getOutputStream();
    os.write(new byte[] {1, 2, 3});
    os.close();
    assertThrows(IOException.class, () -> os.write(new byte[] {9, 9}));
    assertThrows(IOException.class, () -> os.write(new byte[] {9, 9}, 0, 2));
  }

  @Test
  void getInputStreamUnbuffered_whenCalled_behavesLikeBuffered() throws IOException {
    InMemoryUnderlying u = new InMemoryUnderlying();
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(u.mock);

    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      os.write(new byte[50]);
    }
    assertEquals(50, bucket.size());
    try (InputStream in = bucket.getInputStreamUnbuffered()) {
      assertEquals(50, in.available());
      assertEquals(50, in.readNBytes(100).length);
      assertEquals(0, in.available());
      assertEquals(-1, in.read());
    }
  }

  @Test
  void getName_whenCalled_prefixesUnderlyingName() throws IOException {
    InMemoryUnderlying u = new InMemoryUnderlying();
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(u.mock);
    assertEquals("Padded:Underlying", bucket.getName());
  }

  @Test
  void isReadOnly_whenSetReadOnly_returnsTrue() throws IOException {
    InMemoryUnderlying u = new InMemoryUnderlying();
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(u.mock);
    assertFalse(bucket.isReadOnly());
    bucket.setReadOnly();
    assertTrue(bucket.isReadOnly());
  }

  @Test
  void free_whenCalled_delegatesToUnderlying() {
    RandomAccessBucket underlying = mock(RandomAccessBucket.class);
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(underlying);
    bucket.free();
    verify(underlying).free();
  }

  @Test
  void createShadow_whenCalled_returnsReadOnlyCopyWithSameSize() throws IOException {
    RandomAccessBucket underlying = mock(RandomAccessBucket.class);
    RandomAccessBucket shadow = mock(RandomAccessBucket.class);
    when(underlying.createShadow()).thenReturn(shadow);

    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(underlying);
    // Provide a concrete OutputStream for writes performed by the wrapper
    ByteArrayOutputStream underlyingOut = new ByteArrayOutputStream();
    when(underlying.getOutputStream()).thenReturn(underlyingOut);
    when(underlying.getOutputStreamUnbuffered()).thenReturn(underlyingOut);
    try (OutputStream os = bucket.getOutputStream()) {
      os.write(new byte[37]);
    }
    RandomAccessBucket copy = bucket.createShadow();
    assertInstanceOf(PaddedRandomAccessBucket.class, copy);
    PaddedRandomAccessBucket paddedCopy = (PaddedRandomAccessBucket) copy;
    assertSame(shadow, paddedCopy.getUnderlying());
    assertEquals(37, paddedCopy.size());
    assertTrue(paddedCopy.isReadOnly());
  }

  @Test
  void onResume_whenCalled_delegatesToUnderlying() throws Exception {
    RandomAccessBucket underlying = mock(RandomAccessBucket.class);
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(underlying);
    ClientContext ctx = mock(ClientContext.class);
    bucket.onResume(ctx);
    verify(underlying).onResume(ctx);
  }

  @Test
  void storeTo_whenCalled_writesHeaderAndDelegatesUnderlying() throws IOException {
    RandomAccessBucket underlying = mock(RandomAccessBucket.class);
    // Make underlying.storeTo write a sentinel so we can assert ordering
    doAnswer(
            inv -> {
              DataOutputStream dos = inv.getArgument(0);
              dos.writeInt(0x12345678);
              return null;
            })
        .when(underlying)
        .storeTo(any());

    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(underlying, 7L);
    bucket.setReadOnly();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    bucket.storeTo(dos);
    dos.flush();

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
    assertEquals(PaddedRandomAccessBucket.MAGIC, dis.readInt());
    assertEquals(1, dis.readInt());
    assertEquals(7L, dis.readLong());
    assertTrue(dis.readBoolean());
    assertEquals(0x12345678, dis.readInt());
    verify(underlying).storeTo(any());
  }

  @Test
  void toRandomAccessBuffer_whenOutputOpen_throwsIOException() throws IOException {
    RandomAccessBucket underlying = mock(RandomAccessBucket.class);
    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(underlying);
    bucket.getOutputStream(); // leave it open
    IOException ex = assertThrows(IOException.class, bucket::toRandomAccessBuffer);
    assertThat(ex.getMessage(), containsString("Must close first"));
  }

  @Test
  void toRandomAccessBuffer_whenClosed_returnsPaddedRAFAndSetsReadOnly() throws IOException {
    RandomAccessBucket underlying = mock(RandomAccessBucket.class);
    LockableRandomAccessBuffer uRaf = mock(LockableRandomAccessBuffer.class);
    when(underlying.toRandomAccessBuffer()).thenReturn(uRaf);

    PaddedRandomAccessBucket bucket = new PaddedRandomAccessBucket(underlying);
    ByteArrayOutputStream underlyingOut = new ByteArrayOutputStream();
    when(underlying.getOutputStream()).thenReturn(underlyingOut);
    when(underlying.getOutputStreamUnbuffered()).thenReturn(underlyingOut);
    try (OutputStream os = bucket.getOutputStream()) {
      os.write(new byte[11]);
    }
    LockableRandomAccessBuffer wrapped = bucket.toRandomAccessBuffer();
    assertTrue(bucket.isReadOnly());
    verify(underlying).setReadOnly();
    assertNotNull(wrapped);
    assertInstanceOf(PaddedRandomAccessBuffer.class, wrapped);
    assertEquals(11L, wrapped.size());
  }
}
