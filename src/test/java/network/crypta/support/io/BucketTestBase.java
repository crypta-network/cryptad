package network.crypta.support.io;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;

public abstract class BucketTestBase {
  private static final String SIZE_EMPTY_MESSAGE = "Size-0";
  protected static final byte[] dataLong;

  static {
    dataLong = new byte[32768 + 1]; // 32K + 1
    for (int i = 0; i < dataLong.length; i++) {
      dataLong[i] = (byte) i;
    }
  }

  protected byte[] data1 = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  protected byte[] data2 =
      new byte[] {
        0x70,
        (byte) 0x81,
        (byte) 0x92,
        (byte) 0xa3,
        (byte) 0xb4,
        (byte) 0xc5,
        (byte) 0xd6,
        (byte) 0xe7,
        (byte) 0xf8
      };
  protected boolean canOverwrite = true;

  @Test
  void testReadEmpty() throws IOException {
    Bucket bucket = makeBucket(3);
    try {
      assertEquals(0, bucket.size(), SIZE_EMPTY_MESSAGE);
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(new byte[0]);
      }

      // Read byte[]
      byte[] data = new byte[10];
      int read;
      try (InputStream is = bucket.getInputStream()) {
        read = is.read(data, 0, 10);
      }

      assertEquals(-1, read, "Read-Empty");
    } finally {
      freeBucket(bucket);
    }
  }

  @Test
  void testReadExcess() throws IOException {
    Bucket bucket = makeBucket(Math.max(data1.length, data2.length));
    try {
      assertEquals(0, bucket.size(), SIZE_EMPTY_MESSAGE);

      // Write
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(new byte[] {5});
      }

      assertEquals(1, bucket.size(), "Read-Excess-Size");

      // Read byte[]
      byte[] data = new byte[10];
      int read;
      try (InputStream is = bucket.getInputStream()) {
        read = is.read(data, 0, 10);
        assertEquals(1, read, "Read-Excess");
        assertEquals(5, data[0], "Read-Excess-5");

        read = is.read(data, 0, 10);
        assertEquals(-1, read, "Read-Excess-EOF");
      }
    } finally {
      freeBucket(bucket);
    }
  }

  @Test
  void testReadWrite() throws IOException {
    Bucket bucket = makeBucket(Math.max(data1.length, data2.length));
    try {
      assertEquals(0, bucket.size(), SIZE_EMPTY_MESSAGE);

      // Write
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(data1);
      }

      assertEquals(data1.length, bucket.size(), "Size-1");

      // Read byte[]
      byte[] data = new byte[data1.length];
      int read;
      try (InputStream is = bucket.getInputStream()) {
        read = is.read(data, 0, data1.length);
      }

      assertEquals(data1.length, read, "SimpleRead-1-SIZE");
      assertEquals(new ByteArrayWrapper(data1), new ByteArrayWrapper(data), "SimpleRead-1");

      // Read byte
      try (InputStream is = bucket.getInputStream()) {
        for (byte b : data1) {
          assertEquals(b, (byte) is.read(), "SimpleRead-2");
        }

        // EOF
        assertEquals(-1, is.read(new byte[4]), "SimpleRead-EOF0");
        assertEquals(-1, is.read(), "SimpleRead-EOF1");
        assertEquals(-1, is.read(), "SimpleRead-EOF2");
      }
    } finally {
      freeBucket(bucket);
    }
  }

  // Write twice -- should overwrite, not append
  @Test
  void testReuse() throws IOException {
    if (!canOverwrite) {
      return;
    }

    Bucket bucket = makeBucket(Math.max(data1.length, data2.length));
    try {
      // Write
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(data1);
      }

      // Read byte[]
      byte[] data = new byte[data1.length];
      int read;
      try (InputStream is = bucket.getInputStream()) {
        read = is.read(data, 0, data1.length);
      }

      assertEquals(data1.length, read, "Read-1-SIZE");
      assertEquals(new ByteArrayWrapper(data1), new ByteArrayWrapper(data), "Read-1");

      // Write again
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(data2);
      }

      // Read byte[]
      data = new byte[data2.length];
      try (InputStream is = bucket.getInputStream()) {
        read = is.read(data, 0, data2.length);
      }

      assertEquals(data2.length, read, "Read-2-SIZE");
      assertEquals(new ByteArrayWrapper(data2), new ByteArrayWrapper(data), "Read-2");
    } finally {
      freeBucket(bucket);
    }
  }

  @Test
  void testNegative() throws IOException {
    Bucket bucket = makeBucket(Math.max(data1.length, data2.length));
    try {
      // Write
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(0);
        os.write(-1);
        os.write(-2);
        os.write(123);
      }

      // Read byte[]
      try (InputStream is = bucket.getInputStream()) {
        assertEquals(0xff & (byte) 0, is.read(), "Write-0");
        assertEquals(0xff & (byte) -1, is.read(), "Write-1");
        assertEquals(0xff & (byte) -2, is.read(), "Write-2");
        assertEquals(0xff & (byte) 123, is.read(), "Write-123");
        assertEquals(-1, is.read(), "EOF");
      }
    } finally {
      freeBucket(bucket);
    }
  }

  @Test
  void testLargeData() throws IOException {

    Bucket bucket = makeBucket(dataLong.length * 16L);
    try {
      // Write
      try (OutputStream os = bucket.getOutputStream()) {
        for (int i = 0; i < 16; i++) {
          os.write(dataLong);
        }
      }

      // Read byte[]
      try (DataInputStream is = new DataInputStream(bucket.getInputStream())) {
        for (int i = 0; i < 16; i++) {
          byte[] buf = new byte[dataLong.length];
          is.readFully(buf);
          assertEquals(new ByteArrayWrapper(dataLong), new ByteArrayWrapper(buf), "Read-Long");
        }

        int read = is.read(new byte[1]);
        assertEquals(-1, read, "Read-Long-Size");
      }
    } finally {
      freeBucket(bucket);
    }
  }

  protected abstract Bucket makeBucket(long size) throws IOException;

  protected abstract void freeBucket(Bucket bucket) throws IOException;
}
