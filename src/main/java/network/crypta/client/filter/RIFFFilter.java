package network.crypta.client.filter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import network.crypta.l10n.NodeL10n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RIFF file format filter for several formats, such as AVI, WAV, MID, and WebP.
 *
 * <p>This abstract filter reads a stream that begins with the canonical RIFF header (the {@code
 * RIFF} magic followed by a 32-bit little‑endian size) and then iterates over individual chunks.
 * Implementations specify the expected FourCC following the size field (for example, {@code WAVE}
 * for WAV or {@code WEBP} for WebP) and implement {@link #readFilterChunk(byte[], int, Object,
 * ReadFilterContext)} to validate and optionally transform each chunk as it is read. All size
 * arithmetic follows RIFF rules, including padding to even byte boundaries.
 *
 * <p>Use this type as the base for content filters that must parse RIFF containers in a
 * streaming/forward‑only manner. Typical usage is to allocate a small, per‑parse context via {@link
 * #createContext()}, pass bytes through unchanged unless a chunk requires inspection, and then call
 * {@link #eofCheck(Object)} to validate final state once the container has been fully consumed.
 *
 * <ul>
 *   <li>Mutability: the filter itself is stateless; per‑parse state is carried in the context
 *       object returned by {@link #createContext()}.
 *   <li>Thread‑safety: instances are safe to reuse across threads as no mutable instance fields are
 *       used; do not share a single context between concurrent parses.
 *   <li>Error handling: invalid sizes, truncated input, or unexpected chunk identifiers result in a
 *       {@link DataFilterException} with localized messages suitable for presentation to users.
 * </ul>
 *
 * @see ReadFilterContext
 */
public abstract class RIFFFilter implements ContentDataFilter {
  private static final Logger LOG = LoggerFactory.getLogger(RIFFFilter.class);

  private static final byte[] magicNumber = new byte[] {'R', 'I', 'F', 'F'};

  // Localized message keys used repeatedly in this filter.
  private static final String KEY_INVALID_TITLE = "invalidTitle";
  private static final String KEY_DATA_TOO_BIG = "dataTooBig";
  private static final String KEY_EOF_MESSAGE = "ContentFilter.EOFMessage";

  /**
   * Creates a new RIFF filter instance.
   *
   * <p>The base class is stateless; subclasses typically carry no mutable state and rely on the
   * per‑parse context returned by {@link #createContext()} to track validation details.
   */
  protected RIFFFilter() {}

  /**
   * Reads and validates a RIFF container from {@code input}, emits a sanitized or pass‑through
   * representation to {@code output}, and reports progress or metadata via {@code cb}.
   *
   * <p>The method verifies the leading {@code RIFF} magic, checks the declared file size for
   * plausibility (unsigned 32‑bit range and at least the RIFF header length), validates the
   * container type using {@link #getChunkMagicNumber()}, and then iterates over chunks. Each chunk
   * is dispatched to {@link #readFilterChunk(byte[], int, Object, ReadFilterContext)} with an
   * implementation‑defined context created by {@link #createContext()}.
   *
   * <p>Callers provide the original {@code charset} and ancillary parameters via {@code
   * otherParams}. The {@code schemeHostAndPort} is passed through unchanged for use in
   * link‑rewriting filters. When an unrecoverable validation failure occurs, a {@link
   * DataFilterException} is thrown (as a subclass of {@link IOException}).
   *
   * @param input the source of RIFF bytes; must be positioned at the beginning of the file and will
   *     be consumed until EOF or error; never {@code null}
   * @param output the destination to which a validated, possibly unchanged, stream is written; the
   *     caller retains ownership and is responsible for closing; never {@code null}
   * @param charset the character set name associated with the resource when applicable; may be
   *     {@code null} when not relevant to the RIFF subtype being processed
   * @param otherParams a modifiable or read‑only map of auxiliary options and hints supplied by the
   *     caller; keys and values are implementation‑specific and may be empty
   * @param schemeHostAndPort an origin string in the form {@code scheme://host:port} used for
   *     constructing absolute links; may be {@code null} when not applicable
   * @param cb callback for reporting progress or extracted metadata; implementation will call it
   *     zero or more times; may be {@code null} when no callbacks are needed
   * @throws IOException if an I/O error occurs, the stream is truncated, or the content fails
   *     validation producing a {@link DataFilterException}
   */
  @Override
  public void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException {
    DataInputStream in = new DataInputStream(input);
    DataOutputStream out = new DataOutputStream(output);
    for (byte magicCharacter : magicNumber) {
      if (magicCharacter != in.readByte()) {
        throw new DataFilterException(
            l10n(KEY_INVALID_TITLE), l10n(KEY_INVALID_TITLE), l10n("invalidStream"));
      }
    }
    int fileSize = readLittleEndianInt(in);
    for (byte magicCharacter : getChunkMagicNumber()) {
      if (magicCharacter != in.readByte()) {
        throw new DataFilterException(
            l10n(KEY_INVALID_TITLE), l10n(KEY_INVALID_TITLE), l10n("invalidStream"));
      }
    }
    out.write(magicNumber);
    if (fileSize < 0) {
      // RIFF declares sizes as unsigned 32-bit; negative indicates > 2 GiB and is rejected.
      throw new DataFilterException(
          l10n(KEY_INVALID_TITLE), l10n(KEY_INVALID_TITLE), l10n("data2GB"));
    }
    if (fileSize < 12) {
      // There couldn't be any chunk in such a small file
      throw new DataFilterException(
          l10n(KEY_INVALID_TITLE),
          l10n(KEY_INVALID_TITLE),
          NodeL10n.getBase().getString(KEY_EOF_MESSAGE));
    }
    writeLittleEndianInt(out, fileSize);
    out.write(getChunkMagicNumber());

    Object context = createContext();
    byte[] fccType;
    int ckSize;
    int remainingSize = fileSize - 4;
    try {
      do {
        fccType = new byte[4];
        in.readFully(fccType);
        ckSize = readLittleEndianInt(in);
        if (ckSize < 0 || remainingSize < ckSize + 8 + (ckSize & 1)) {
          throw new DataFilterException(
              l10n(KEY_INVALID_TITLE), l10n(KEY_INVALID_TITLE), l10n(KEY_DATA_TOO_BIG));
        }
        remainingSize -= ckSize + 8 + (ckSize & 1);
        readFilterChunk(
            fccType,
            ckSize,
            context,
            new ReadFilterContext(in, out, charset, otherParams, schemeHostAndPort, cb));
      } while (remainingSize != 0);
    } catch (EOFException e) {
      throw new DataFilterException(
          l10n(KEY_INVALID_TITLE),
          l10n(KEY_INVALID_TITLE),
          NodeL10n.getBase().getString(KEY_EOF_MESSAGE));
    }
    // Testing if there is any unprocessed bytes left
    if (input.read() != -1) {
      // A byte is after expected EOF
      throw new DataFilterException(
          l10n(KEY_INVALID_TITLE),
          l10n(KEY_INVALID_TITLE),
          NodeL10n.getBase().getString(KEY_EOF_MESSAGE));
    }
    // Final validation delegated to the implementation.
    eofCheck(context);
  }

  /**
   * Returns the FourCC immediately following the {@code RIFF} header that identifies the specific
   * RIFF form handled by this filter (for example, {@code WAVE}, {@code AVI }, or {@code WEBP}).
   *
   * @return an array of exactly four ASCII bytes forming the expected container identifier; callers
   *     and implementations must not modify the returned array
   */
  protected abstract byte[] getChunkMagicNumber();

  /**
   * Creates a new per‑parse context object used to accumulate state across chunk callbacks.
   *
   * <p>The returned object is opaque to the base class; implementations define its type and
   * contents. A fresh instance is created for each call to {@link #readFilter(InputStream,
   * OutputStream, String, Map, String, FilterCallback)} and must not be shared across concurrent
   * parses.
   *
   * @return an implementation‑defined context instance that carries parsing state until {@link
   *     #eofCheck(Object)} is invoked
   */
  protected abstract Object createContext();

  /**
   * Holder for parameters commonly passed to {@link #readFilterChunk(byte[], int, Object,
   * ReadFilterContext)}.
   */
  protected static final class ReadFilterContext {
    /**
     * Data input stream wrapping the caller-provided {@link InputStream}. Implementations read
     * chunk payloads from this stream using RIFF little‑endian conventions. The stream position
     * advances as chunks are consumed and must not be used after the filter completes.
     */
    public final DataInputStream input;

    /**
     * Data output stream that receives validated or pass‑through bytes. Implementations may write
     * directly to this stream to mirror input chunks or to emit a sanitized representation.
     */
    public final DataOutputStream output;

    /**
     * Declared or inferred character set name relevant to some RIFF subtypes (for example, text
     * metadata). The value may be {@code null} when character encoding does not apply.
     */
    public final String charset;

    /**
     * Auxiliary parameters provided by the caller. Keys and values are filter‑specific and may be
     * empty. Implementations should treat the map as read‑only unless documented otherwise.
     */
    public final Map<String, String> otherParams;

    /**
     * The origin string ({@code scheme://host:port}) appropriate for link resolution in filters
     * that rewrite URLs. May be {@code null} when not applicable to the RIFF subtype.
     */
    public final String schemeHostAndPort;

    /**
     * Callback invoked by some filters to report progress or extracted metadata. May be {@code
     * null} when the caller does not require callbacks.
     */
    public final FilterCallback callback;

    /**
     * Constructs a context object that aggregates common resources and caller-specified options for
     * use during RIFF parsing.
     *
     * @param input data input stream from which chunk payloads are read; must not be {@code null}
     * @param output data output stream that receives validated bytes; must not be {@code null}
     * @param charset character set name associated with the resource, or {@code null} if not
     *     applicable
     * @param otherParams implementation‑specific options and hints; may be empty but never {@code
     *     null}
     * @param schemeHostAndPort origin in the form {@code scheme://host:port} used by link‑rewriting
     *     filters; may be {@code null}
     * @param callback callback interface for progress or metadata reporting; may be {@code null}
     */
    ReadFilterContext(
        DataInputStream input,
        DataOutputStream output,
        String charset,
        Map<String, String> otherParams,
        String schemeHostAndPort,
        FilterCallback callback) {
      this.input = input;
      this.output = output;
      this.charset = charset;
      this.otherParams = otherParams;
      this.schemeHostAndPort = schemeHostAndPort;
      this.callback = callback;
    }
  }

  /**
   * Processes a single RIFF chunk and writes any validated output as needed.
   *
   * <p>Implementations must consume exactly {@code size} bytes from {@code params.input} (plus a
   * padding byte when {@code size} is odd per RIFF rules) and may write zero or more bytes to
   * {@code params.output}. The {@code context} should be updated as necessary to reflect parsed
   * state that is validated later in {@link #eofCheck(Object)}.
   *
   * @param id four‑byte chunk identifier as read from the stream; not reused after the call and may
   *     be modified by the implementation
   * @param size chunk payload size in bytes (not including the header); must be respected exactly
   *     when consuming from the input stream
   * @param context implementation‑defined context object previously created by {@link
   *     #createContext()}; used to accumulate validation state across chunks
   * @param params aggregated read parameters and helpers, including input/output streams and caller
   *     options
   * @throws IOException if a read/write error occurs, the chunk is truncated, or validation fails
   *     resulting in a {@link DataFilterException}
   */
  protected abstract void readFilterChunk(
      byte[] id, int size, Object context, ReadFilterContext params) throws IOException;

  /**
   * Performs final validation after the RIFF container has been fully consumed.
   *
   * <p>Implementations examine the state accumulated in {@code context} to detect missing or
   * inconsistent structures that cannot be verified on a per‑chunk basis. No I/O should occur in
   * this method.
   *
   * @param context the implementation‑defined context created by {@link #createContext()} and
   *     updated during {@link #readFilterChunk(byte[], int, Object, ReadFilterContext)} calls
   * @throws DataFilterException if the parsed data violates format invariants or a required chunk
   *     was not encountered; callers should treat this as a validation failure
   */
  protected abstract void eofCheck(Object context) throws DataFilterException;

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("RIFFFilter." + key);
  }

  /**
   * Copies {@code size} bytes from {@code in} to {@code out} without interpretation.
   *
   * <p>Data is transferred in chunks up to 1 MiB to avoid large temporary buffers. A negative size
   * triggers a {@link DataFilterException} indicating an implausible or malicious RIFF chunk size.
   *
   * @param in input stream to read from; must contain at least {@code size} bytes available or an
   *     {@link EOFException} will be raised by read operations
   * @param out output stream to write to; receives exactly {@code size} bytes on success; never
   *     {@code null}
   * @param size number of bytes to copy verbatim; must be zero or greater
   * @throws DataFilterException if {@code size} is negative or otherwise violates RIFF constraints
   * @throws IOException if an underlying I/O error occurs while reading or writing the data
   */
  protected void passthroughBytes(DataInputStream in, DataOutputStream out, int size)
      throws IOException {
    if (size < 0) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("RIFF block size {} is less than 0", size);
      }
      throw new DataFilterException(
          l10n(KEY_INVALID_TITLE), l10n(KEY_INVALID_TITLE), l10n(KEY_DATA_TOO_BIG));
    } else {
      // Copy 1MB at a time instead of all at once
      int section;
      int remaining = size;
      section = Math.min(remaining, 1024 * 1024);
      byte[] buf = new byte[section];
      while (remaining > 0) {
        section = Math.min(remaining, 1024 * 1024);
        in.readFully(buf, 0, section);
        out.write(buf, 0, section);
        remaining -= section;
      }
    }
  }

  /**
   * Emits a {@code JUNK} chunk of {@code size} bytes filled with zeros, consuming the corresponding
   * payload from {@code in}.
   *
   * <p>The method skips the incoming payload (rounded up to an even size per RIFF rules), then
   * writes a matching {@code JUNK} header and zero‑filled body to {@code out}. This is useful for
   * discarding unsupported or unsafe chunks while preserving container structure.
   *
   * @param in input stream supplying the bytes to discard; must contain at least {@code size}
   *     bytes, rounded up to an even length
   * @param out output stream that receives the {@code JUNK} chunk and padding
   * @param size size of the original chunk payload in bytes; if odd, one byte of padding is added
   *     to satisfy RIFF alignment requirements
   * @throws DataFilterException if {@code size} is negative or exceeds remaining container space
   * @throws IOException if reading from {@code in} or writing to {@code out} fails for any reason
   */
  protected void writeJunkChunk(DataInputStream in, DataOutputStream out, int size)
      throws IOException {
    size += size % 2; // Add a padding if necessary
    if (in.skip(size) < size) {
      // EOFException?
      throw new EOFException();
    }
    if (size < 0) {
      if (LOG.isWarnEnabled()) {
        LOG.warn("RIFF block size {} is less than 0", size);
      }
      throw new DataFilterException(
          l10n(KEY_INVALID_TITLE), l10n(KEY_INVALID_TITLE), l10n(KEY_DATA_TOO_BIG));
    } else {
      // Write 1MB at a time instead of all at once
      int section;
      int remaining = size;
      byte[] zeros = new byte[1024 * 1024];
      for (int i = 0; i < 1024 * 1024; i++) {
        zeros[i] = 0;
      }
      byte[] junk = new byte[] {'J', 'U', 'N', 'K'};
      out.write(junk);
      writeLittleEndianInt(out, size);
      while (remaining > 0) {
        section = Math.min(remaining, 1024 * 1024);
        out.write(zeros, 0, section);
        remaining -= section;
      }
    }
  }

  /**
   * Reads a 32‑bit little‑endian integer from the supplied data stream.
   *
   * <p>{@link DataInputStream#readInt()} and {@link DataOutputStream#writeInt(int)} use big‑endian
   * byte order; RIFF encodes multi‑byte numeric values in little‑endian order. This helper reverses
   * the byte order of {@code readInt()} to match RIFF semantics.
   *
   * @param stream data input to read from; the method consumes exactly four bytes
   * @return the 32‑bit value interpreted as little‑endian; note that RIFF fields may be used as
   *     unsigned values by callers
   * @throws IOException if the stream ends before four bytes are available or another I/O error
   *     occurs
   */
  protected static int readLittleEndianInt(DataInputStream stream) throws IOException {
    int a;
    a = stream.readInt();
    return Integer.reverseBytes(a);
  }

  /**
   * Writes a 32‑bit integer to the supplied data stream in little‑endian byte order.
   *
   * <p>RIFF requires little‑endian encoding for multi‑byte values. This helper reverses the byte
   * order of {@link DataOutputStream#writeInt(int)} to satisfy that requirement.
   *
   * @param stream data output to write to; must be open and writable
   * @param a the 32‑bit value to persist in little‑endian order; callers should ensure values that
   *     conceptually represent unsigned quantities are within the valid 32‑bit range
   * @throws IOException if an I/O error occurs while writing the four bytes
   */
  protected static void writeLittleEndianInt(DataOutputStream stream, int a) throws IOException {
    stream.writeInt(Integer.reverseBytes(a));
  }
}
