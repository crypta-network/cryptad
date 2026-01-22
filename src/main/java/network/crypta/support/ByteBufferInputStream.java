package network.crypta.support;

import java.io.DataInput;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import org.jetbrains.annotations.NotNull;

/**
 * An {@link InputStream} implementation backed by a {@link ByteBuffer}.
 *
 * <p>This stream exposes sequential read access over the remaining region of a provided {@code
 * ByteBuffer} (or over a wrapped byte array). Primitive reads delegate to the underlying buffer
 * (e.g., {@link ByteBuffer#getInt()}), therefore, they use the buffer's current byte order (default
 * is big-endian unless the buffer was created/modified with a different order).
 *
 * <p>Instances are not thread-safe. The buffer position advances as data is read. No copying is
 * performed by the constructors; the stream reflects the provided buffer's state.
 *
 * @author sdiz
 */
public class ByteBufferInputStream extends InputStream {
  /**
   * The backing buffer. Reads advance its position. The buffer's byte order controls the semantics
   * of multibyte reads.
   */
  protected ByteBuffer buf;

  private final DataInput dataInputView =
      new DataInput() {
        @Override
        public void readFully(byte @NotNull [] b) throws IOException {
          ByteBufferInputStream.this.readFully(b);
        }

        @Override
        public void readFully(byte @NotNull [] b, int off, int len) throws IOException {
          ByteBufferInputStream.this.readFully(b, off, len);
        }

        @Override
        public int skipBytes(int n) {
          return ByteBufferInputStream.this.skipBytes(n);
        }

        @Override
        public boolean readBoolean() throws IOException {
          return ByteBufferInputStream.this.readBoolean();
        }

        @Override
        public byte readByte() throws IOException {
          return ByteBufferInputStream.this.readByte();
        }

        @Override
        public int readUnsignedByte() throws IOException {
          return ByteBufferInputStream.this.readUnsignedByte();
        }

        @Override
        public short readShort() throws IOException {
          return ByteBufferInputStream.this.readShort();
        }

        @Override
        public int readUnsignedShort() throws IOException {
          return ByteBufferInputStream.this.readUnsignedShort();
        }

        @Override
        public char readChar() throws IOException {
          return ByteBufferInputStream.this.readChar();
        }

        @Override
        public int readInt() throws IOException {
          return ByteBufferInputStream.this.readInt();
        }

        @Override
        public long readLong() throws IOException {
          return ByteBufferInputStream.this.readLong();
        }

        @Override
        public float readFloat() throws IOException {
          return ByteBufferInputStream.this.readFloat();
        }

        @Override
        public double readDouble() throws IOException {
          return ByteBufferInputStream.this.readDouble();
        }

        @Override
        public String readLine() {
          throw new UnsupportedOperationException("readLine is deprecated");
        }

        @Override
        public @NotNull String readUTF() throws IOException {
          return DataInputStream.readUTF(this);
        }
      };

  /**
   * Creates a stream over the entire {@code array}.
   *
   * @param array the bytes to read from; must not be {@code null}
   */
  public ByteBufferInputStream(byte[] array) {
    this(array, 0, array.length);
  }

  /**
   * Creates a stream over a slice of {@code array}.
   *
   * @param array the source bytes; must not be {@code null}
   * @param offset the starting index (inclusive)
   * @param length the number of bytes exposed by the stream
   * @throws IndexOutOfBoundsException if {@code offset} or {@code length} are out of bounds
   */
  public ByteBufferInputStream(byte[] array, int offset, int length) {
    this(ByteBuffer.wrap(array, offset, length));
  }

  /**
   * Creates a stream over the remaining portion of {@code buf}.
   *
   * <p>No defensive copy is made. The stream reads from the buffer's current position up to its
   * limit. The buffer's byte order is honored for multibyte reads.
   *
   * @param buf the backing buffer; must not be {@code null}
   */
  public ByteBufferInputStream(ByteBuffer buf) {
    this.buf = buf;
  }

  /**
   * Reads a single unsigned byte.
   *
   * @return the next byte value in the range {@code 0..255}, or {@code -1} if no bytes remain
   * @throws IOException never thrown by this implementation; declared for {@link InputStream}
   */
  @Override
  public int read() throws IOException {
    if (!buf.hasRemaining()) {
      return -1;
    }
    return Byte.toUnsignedInt(buf.get());
  }

  /**
   * Reads up to {@code len} bytes into {@code b}.
   *
   * <p>Unlike the general {@link InputStream} contract, this implementation returns {@code 0} when
   * no bytes remain (even if {@code len > 0}). If {@code len == 0}, this method also returns {@code
   * 0}. On success, the buffer position advances by the number of bytes copied.
   *
   * @param b destination array; must not be {@code null}
   * @param off start offset in the destination array
   * @param len maximum number of bytes to read
   * @return the number of bytes read (possibly {@code 0})
   * @throws IndexOutOfBoundsException if {@code off} or {@code len} are invalid for {@code b}
   * @throws IOException never thrown by this implementation; declared for {@link InputStream}
   */
  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    int read = Math.min(len, buf.remaining());
    buf.get(b, off, read);
    return read;
  }

  /**
   * Returns the number of unread bytes left in the stream.
   *
   * @return remaining byte count (non-negative)
   */
  public int remaining() {
    return buf.remaining();
  }

  /**
   * Reads a boolean value.
   *
   * @return {@code true} if the next byte is non-zero; {@code false} otherwise
   * @throws EOFException if fewer than 1 byte remains
   * @throws IOException if an I/O error occurs
   */
  public boolean readBoolean() throws IOException {
    try {
      return buf.get() != 0;
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads a signed byte.
   *
   * @return the next byte
   * @throws EOFException if fewer than 1 byte remains
   * @throws IOException if an I/O error occurs
   */
  public byte readByte() throws IOException {
    try {
      return buf.get();
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads a {@code char} using the buffer's byte order.
   *
   * @return the next character
   * @throws EOFException if fewer than 2 bytes remain
   * @throws IOException if an I/O error occurs
   */
  public char readChar() throws IOException {
    try {
      return buf.getChar();
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads a {@code double} using the buffer's byte order.
   *
   * @return the next double value
   * @throws EOFException if fewer than 8 bytes remain
   * @throws IOException if an I/O error occurs
   */
  public double readDouble() throws IOException {
    try {
      return buf.getDouble();
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads a {@code float} using the buffer's byte order.
   *
   * @return the next float value
   * @throws EOFException if fewer than 4 bytes remain
   * @throws IOException if an I/O error occurs
   */
  public float readFloat() throws IOException {
    try {
      return buf.getFloat();
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads bytes fully into the destination array.
   *
   * @param b the destination array; must not be {@code null}
   * @throws EOFException if fewer bytes remain than {@code b.length}
   * @throws IOException if an I/O error occurs
   */
  public void readFully(byte @NotNull [] b) throws IOException {
    try {
      buf.get(b);
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads bytes fully into a subrange of the destination array.
   *
   * @param b destination array; must not be {@code null}
   * @param off start offset in {@code b}
   * @param len number of bytes to read
   * @throws EOFException if fewer than {@code len} bytes remain
   * @throws IndexOutOfBoundsException if {@code off} or {@code len} are invalid
   * @throws IOException if an I/O error occurs
   */
  public void readFully(byte @NotNull [] b, int off, int len) throws IOException {
    try {
      buf.get(b, off, len);
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads a 32-bit signed integer using the buffer's byte order.
   *
   * @return the next int value
   * @throws EOFException if fewer than 4 bytes remain
   * @throws IOException if an I/O error occurs
   */
  public int readInt() throws IOException {
    try {
      return buf.getInt();
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads a 64-bit signed integer using the buffer's byte order.
   *
   * @return the next long value
   * @throws EOFException if fewer than 8 bytes remain
   * @throws IOException if an I/O error occurs
   */
  public long readLong() throws IOException {
    try {
      return buf.getLong();
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads a 16-bit signed integer using the buffer's byte order.
   *
   * @return the next short value
   * @throws EOFException if fewer than 2 bytes remain
   * @throws IOException if an I/O error occurs
   */
  public short readShort() throws IOException {
    try {
      return buf.getShort();
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads an unsigned byte and returns it as an {@code int}.
   *
   * @return value in {@code 0..255}
   * @throws EOFException if fewer than 1 byte remains
   * @throws IOException if an I/O error occurs
   */
  public int readUnsignedByte() throws IOException {
    try {
      return buf.get() & 0xFF;
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Reads an unsigned 16-bit value and returns it as an {@code int}.
   *
   * @return value in {@code 0..65535}
   * @throws EOFException if fewer than 2 bytes remain
   * @throws IOException if an I/O error occurs
   */
  public int readUnsignedShort() throws IOException {
    try {
      return buf.getShort() & 0xFFFF;
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }

  /**
   * Skips up to {@code n} bytes by advancing the buffer position.
   *
   * @param n the requested number of bytes to skip (non-negative)
   * @return the actual number of bytes skipped (may be less than {@code n})
   */
  public int skipBytes(int n) {
    int skip = Math.min(n, buf.remaining());
    buf.position(buf.position() + skip);
    return skip;
  }

  /**
   * Reads a string encoded with {@link DataInputStream#readUTF(DataInput)} (modified UTF-8).
   *
   * <p>This delegates to {@link DataInputStream#readUTF(DataInput)} with {@code this} as the input
   * source.
   *
   * @return the decoded string
   * @throws EOFException if the stream ends prematurely
   * @throws IOException if an I/O error occurs or the UTF data is malformed
   */
  public @NotNull String readUTF() throws IOException {
    return DataInputStream.readUTF(dataInputView);
  }

  /**
   * Returns a {@link DataInput} view over this stream.
   *
   * <p>The returned view shares this stream's position and byte order.
   *
   * @return a {@link DataInput} that reads from this stream
   */
  public DataInput asDataInput() {
    return dataInputView;
  }

  /**
   * Returns a new stream that exposes the next {@code size} bytes as a view.
   *
   * <p>The returned stream is backed by a {@link ByteBuffer#slice()} of the remaining region and
   * reflects the same byte order. On success, this stream's position advances by {@code size} so
   * later reads continue after the slice.
   *
   * @param size number of bytes to expose in the slice
   * @return a new {@code ByteBufferInputStream} reading exactly {@code size} bytes
   * @throws EOFException if fewer than {@code size} bytes remain
   * @throws IllegalArgumentException if {@code size} is negative
   * @throws IOException if an I/O error occurs
   */
  public ByteBufferInputStream slice(int size) throws IOException {
    try {
      if (buf.remaining() < size) throw new EOFException();

      ByteBuffer bf2 = buf.slice();
      bf2.limit(size);

      // Advance the position of the backing buffer by the sliced size.
      buf.position(buf.position() + size);

      return new ByteBufferInputStream(bf2);
    } catch (BufferUnderflowException e) {
      throw (EOFException) new EOFException().initCause(e);
    }
  }
}
