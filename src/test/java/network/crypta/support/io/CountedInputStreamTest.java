package network.crypta.support.io;

import java.io.IOException;
import java.io.InputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S5778")
class CountedInputStreamTest {

  @Test
  void constructor_whenNullInput_expectIllegalStateException() {
    assertThrows(
        IllegalStateException.class,
        () -> {
          try (var _ = new CountedInputStream(null)) {
            fail("unreachable");
          }
        });
  }

  @Test
  void count_whenNoOperations_expectZero() throws IOException {
    InputStream in = mock(InputStream.class);
    try (CountedInputStream cis = new CountedInputStream(in)) {
      assertEquals(0L, cis.count());
    }
  }

  @ParameterizedTest
  @CsvSource({"-1,0", "0,1", "42,1"})
  void read_whenSingleByteVariousReturn_expectCountAccumulates(int delegateReturn, long expectedInc)
      throws IOException {
    InputStream in = mock(InputStream.class);
    when(in.read()).thenReturn(delegateReturn);
    try (CountedInputStream cis = new CountedInputStream(in)) {
      int ret = cis.read();
      assertEquals(delegateReturn, ret);
      assertEquals(expectedInc, cis.count());
    }
    verify(in, times(1)).read();
  }

  @ParameterizedTest
  @CsvSource({"-1,0", "0,0", "5,5"})
  void read_whenByteArrayVariousReturn_expectCountAccumulates(int delegateReturn, long expectedInc)
      throws IOException {
    byte[] buf = new byte[8];
    InputStream in = mock(InputStream.class);
    when(in.read(any(byte[].class))).thenReturn(delegateReturn);
    try (CountedInputStream cis = new CountedInputStream(in)) {
      int ret = cis.read(buf);
      assertEquals(delegateReturn, ret);
      assertEquals(expectedInc, cis.count());
    }
    network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
        verify(in, times(1)).read(same(buf)));
  }

  @ParameterizedTest
  @CsvSource({"-1,0", "0,0", "4,4"})
  void read_whenByteArrayWithOffsetVariousReturn_expectCountAccumulates(
      int delegateReturn, long expectedInc) throws IOException {
    byte[] buf = new byte[16];
    int off = 3;
    int len = 7;
    InputStream in = mock(InputStream.class);
    when(in.read(any(byte[].class), eq(off), eq(len))).thenReturn(delegateReturn);
    try (CountedInputStream cis = new CountedInputStream(in)) {
      int ret = cis.read(buf, off, len);
      assertEquals(delegateReturn, ret);
      assertEquals(expectedInc, cis.count());
    }
    network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
        verify(in, times(1)).read(same(buf), eq(off), eq(len)));
  }

  @ParameterizedTest
  @CsvSource({"-5,0", "0,0", "7,7"})
  void skip_whenDelegateReturnsVarious_expectCountAccumulates(long delegateReturn, long expectedInc)
      throws IOException {
    InputStream in = mock(InputStream.class);
    when(in.skip(anyLong())).thenReturn(delegateReturn);
    try (CountedInputStream cis = new CountedInputStream(in)) {
      long ret = cis.skip(10L);
      assertEquals(delegateReturn, ret);
      assertEquals(expectedInc, cis.count());
    }
    network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(verify(in, times(1)).skip(10L));
  }

  @Test
  void read_whenNullBuffer_expectNPEAndNoCountChange() throws IOException {
    InputStream in = mock(InputStream.class);
    when(in.read((byte[]) isNull())).thenThrow(new NullPointerException("buf"));
    try (CountedInputStream cis = new CountedInputStream(in)) {
      //noinspection DataFlowIssue
      assertThrows(
          NullPointerException.class,
          () -> {
            network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(cis.read(null));
          });
      assertEquals(0L, cis.count());
    }
  }

  @Test
  void read_whenInvalidOffsetLength_delegateThrows_expectNoCountChange() throws IOException {
    byte[] buf = new byte[4];
    InputStream in = mock(InputStream.class);
    when(in.read(same(buf), eq(-1), eq(2))).thenThrow(new IndexOutOfBoundsException("off < 0"));
    try (CountedInputStream cis = new CountedInputStream(in)) {
      int invalidOffset = Integer.parseInt("-1");
      assertThrows(
          IndexOutOfBoundsException.class,
          () -> {
            network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
                cis.read(buf, invalidOffset, 2));
          });
      assertEquals(0L, cis.count());
    }
  }

  @Test
  void skip_whenDelegateSkipsLessThanRequested_expectCountByReturned() throws IOException {
    InputStream in = mock(InputStream.class);
    when(in.skip(5L)).thenReturn(2L);
    try (CountedInputStream cis = new CountedInputStream(in)) {
      long ret = cis.skip(5L);
      assertEquals(2L, ret);
      assertEquals(2L, cis.count());
    }
    network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(verify(in, times(1)).skip(5L));
  }

  @Test
  void count_whenMultipleOperations_expectSum() throws IOException {
    InputStream in = mock(InputStream.class);
    try (CountedInputStream cis = new CountedInputStream(in)) {
      when(in.read()).thenReturn(0); // one byte read (value 0)
      int b = cis.read();
      assertEquals(0, b);

      byte[] buf1 = new byte[10];
      when(in.read(same(buf1), eq(1), eq(3))).thenReturn(3);
      int r1 = cis.read(buf1, 1, 3);
      assertEquals(3, r1);

      byte[] buf2 = new byte[5];
      when(in.read(same(buf2))).thenReturn(2);
      int r2 = cis.read(buf2);
      assertEquals(2, r2);

      when(in.skip(5L)).thenReturn(4L);
      long s = cis.skip(5L);
      assertEquals(4L, s);

      assertEquals(1L + 3L + 2L + 4L, cis.count());
    }
  }
}
