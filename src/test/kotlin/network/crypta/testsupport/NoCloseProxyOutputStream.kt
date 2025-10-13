package network.crypta.testsupport

import java.io.FilterOutputStream
import java.io.OutputStream

/**
 * OutputStream wrapper that prevents closing the underlying stream.
 *
 * Used in tests where we need to continue writing to the original stream after a decorated stream
 * has been closed (e.g., to append extra bytes to verify authentication/tag checks). The wrapper
 * flushes on [close] but does not propagate the close to the delegate.
 */
class NoCloseProxyOutputStream(out: OutputStream) : FilterOutputStream(out) {
  override fun write(b: ByteArray, off: Int, len: Int) {
    out.write(b, off, len)
  }

  override fun close() {
    // Intentionally do not close the underlying stream; just flush it to keep
    // test behavior deterministic.
    flush()
  }
}
