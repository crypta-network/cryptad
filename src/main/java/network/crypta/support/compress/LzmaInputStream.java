package network.crypta.support.compress;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import org.jetbrains.annotations.NotNull;
import org.sevenzip.compression.lzma.Decoder;

/**
 * Streaming LZMA decoder exposed as a standard {@link InputStream}.
 *
 * <p>Reads 5-byte coder properties plus an 8-byte little-endian uncompressed size header.
 */
public final class LzmaInputStream extends InputStream {
  private final InputStream source;
  private final PipedInputStream pipeIn = new PipedInputStream();
  private final PipedOutputStream pipeOut;
  private final CountDownLatch started = new CountDownLatch(1);
  private final AtomicReference<IOException> thrown = new AtomicReference<>();

  public LzmaInputStream(InputStream source) throws IOException {
    this.source = source;
    this.pipeOut = new PipedOutputStream(pipeIn);
    Thread worker = new Thread(this::decodeLoop, "LZMA-Decoder");
    worker.setDaemon(true);
    worker.start();
    try {
      started.await();
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while starting LZMA decoder", ie);
    }
    IOException constructorError = thrown.get();
    if (constructorError != null) {
      throw constructorError;
    }
  }

  private void decodeLoop() {
    try (BufferedInputStream inBuf = new BufferedInputStream(source);
        PipedOutputStream out = pipeOut) {
      byte[] props = new byte[5];
      readFully(inBuf, props);

      long outSize = 0L;
      for (int i = 0; i < 8; i++) {
        int b = inBuf.read();
        if (b < 0) {
          throw new IOException("Unexpected EOF reading LZMA size header");
        }
        outSize |= (b & 0xFFL) << (8 * i);
      }

      Decoder decoder = new Decoder();
      if (!decoder.setDecoderProperties(props)) {
        throw new IOException("Invalid LZMA properties");
      }
      started.countDown();

      if (!decoder.code(inBuf, out, outSize)) {
        throw new IOException("LZMA decode error");
      }
      out.flush();
    } catch (IOException ioe) {
      thrown.set(ioe);
      started.countDown();
      try {
        pipeOut.close();
      } catch (IOException _) {
        // Pipe may already be closed.
      }
    }
  }

  private static void readFully(InputStream input, byte[] buf) throws IOException {
    int pos = 0;
    while (pos < buf.length) {
      int r = input.read(buf, pos, buf.length - pos);
      if (r < 0) {
        throw new IOException("Unexpected EOF");
      }
      pos += r;
    }
  }

  @Override
  public int read() throws IOException {
    IOException readError = thrown.get();
    if (readError != null) {
      throw readError;
    }
    int b = pipeIn.read();
    IOException eofError = thrown.get();
    if (b < 0 && eofError != null) {
      throw eofError;
    }
    return b;
  }

  @Override
  public int read(byte @NotNull [] b, int off, int len) throws IOException {
    IOException readError = thrown.get();
    if (readError != null) {
      throw readError;
    }
    int r = pipeIn.read(b, off, len);
    IOException eofError = thrown.get();
    if (r < 0 && eofError != null) {
      throw eofError;
    }
    return r;
  }

  @Override
  public void close() throws IOException {
    try (var _ = source) {
      pipeIn.close();
    }
  }
}
