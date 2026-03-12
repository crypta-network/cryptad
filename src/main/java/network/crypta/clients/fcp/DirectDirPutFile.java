package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.NullBucket;

/**
 * DirectDirPutFile represents a manifest entry whose bytes arrive inline with the FCP command
 * stream.
 *
 * <p>The class is instantiated during request parsing whenever a client selects {@code
 * UploadFrom=direct}. It captures the required {@code DataLength}, eagerly sizes a {@link
 * RandomAccessBucket}, and exposes streaming helpers so manifest builders can read directly from
 * the client connection without temporarily constructing disk manifests. Callers typically place
 * the resulting instance into a {@code ClientPutComplexDir} workflow to assemble directories that
 * mix streamed and disk-backed files.
 *
 * <p>The instance owns its bucket for the lifetime of the upload, guaranteeing that read lengths
 * stay immutable and that the stored data can be replayed multiple times (for hashing, retries, or
 * manifest serialization) by calling {@link #getData()} as needed. No synchronization is provided;
 * callers should confine each object to the thread coordinating the associated FCP request to avoid
 * concurrent reads against the same bucket handles.
 *
 * <p>Because the implementation deals with user-controlled input sizes, it assumes that the
 * surrounding {@link BucketFactory} enforces quota or spilling policies appropriate for the node's
 * resource limits. Large uploads therefore stream directly into the staging bucket, while tiny ones
 * may remain purely in-memory, giving operators predictable behavior regardless of payload size.
 *
 * <ul>
 *   <li>Validates that {@code DataLength} exists and parses cleanly.
 *   <li>Allocates a bucket sized for the declared payload before bytes are received.
 *   <li>Provides directional copy helpers for sockets and manifest serialization stages.
 * </ul>
 *
 * @see DirPutFile
 * @see DiskDirPutFile
 */
public class DirectDirPutFile extends DirPutFile {

  private final RandomAccessBucket data;
  private final long length;

  /**
   * Builds a {@link DirectDirPutFile} for a {@code UploadFrom=direct} manifest element.
   *
   * <p>The factory extracts the {@code DataLength} from the provided {@link SimpleFieldSet},
   * verifies that it is numeric, and immediately obtains a {@link RandomAccessBucket} of matching
   * size from the supplied {@link BucketFactory}. The MIME type is inherited either from the
   * explicit {@code Metadata.ContentType} that the caller resolved earlier or from the default
   * guessing heuristics exposed by {@link DirPutFile#guessMIME(String)}. Any allocation or parsing
   * problem translates into a {@link MessageInvalidException} whose error code mirrors the exact
   * fault so the requesting client receives actionable diagnostics.
   *
   * <pre>{@code
   * DirectDirPutFile file = DirectDirPutFile.create(
   *     "docs/readme.txt", null, fields, requestId, false, bucketFactory);
   * file.read(clientInputStream);
   * }</pre>
   *
   * @param name manifest-relative entry name chosen by the client; must be non-null and stable.
   * @param contentTypeOverride optional MIME token supplied earlier; {@code null} triggers
   *     guessing.
   * @param subset parsed FCP message subset containing at least {@code DataLength} metadata.
   * @param identifier unique request identifier echoed in error messages sent back to the user.
   * @param global whether protocol errors should be flagged as globally broadcast messages.
   * @param bf bucket factory responsible for providing appropriately sized staging buckets.
   * @return fully initialized {@code DirectDirPutFile} ready to receive {@link #read(InputStream)}
   *     bytes.
   * @throws MessageInvalidException if {@code DataLength} is missing, malformed, or the bucket
   *     allocation fails for the requested size.
   */
  public static DirectDirPutFile create(
      String name,
      String contentTypeOverride,
      SimpleFieldSet subset,
      String identifier,
      boolean global,
      BucketFactory bf)
      throws MessageInvalidException {
    String s = subset.get("DataLength");
    if (s == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "UploadFrom=direct requires a DataLength for " + name,
          identifier,
          global);
    long length;
    RandomAccessBucket data;
    try {
      length = Long.parseLong(s);
    } catch (NumberFormatException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ERROR_PARSING_NUMBER,
          "Could not parse DataLength: " + e,
          identifier,
          global);
    }
    try {
      if (length == 0) data = new NullBucket();
      else data = bf.makeBucket(length);
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INTERNAL_ERROR,
          "Internal error: could not allocate temp bucket: " + e,
          identifier,
          global);
    }
    String mimeType;
    if (contentTypeOverride == null) mimeType = DirPutFile.guessMIME(name);
    else mimeType = contentTypeOverride;
    return new DirectDirPutFile(name, mimeType, length, data);
  }

  private DirectDirPutFile(String name, String mimeType, long length, RandomAccessBucket data) {
    super(name, mimeType);
    this.length = length;
    this.data = data;
  }

  /**
   * Reports the exact byte count that must still be copied from the client connection.
   *
   * <p>The value equals the {@code DataLength} parsed during creation and never changes afterward,
   * making it safe to use for progress reporting, rate limiting, or pre-sizing manifest builders.
   * Because {@link BucketFactory} allocated storage to match this number, exceeding it would
   * indicate a client protocol error, whereas providing fewer bytes would leave the bucket
   * partially empty and eventually cause downstream integrity checks to fail.
   *
   * @return immutable byte length declaration for the staged upload payload.
   */
  public long bytesToRead() {
    return length;
  }

  /**
   * Streams {@link InputStream} data into the staging bucket until the declared length is reached.
   *
   * <p>The method consumes exactly {@link #bytesToRead()} bytes, delegating to {@link
   * BucketTools#copyFrom(network.crypta.support.api.Bucket, java.io.InputStream, long)} so short
   * reads, premature EOF, or transport errors surface as {@link IOException}s. Callers are
   * responsible for providing a blocking stream that delivers at least the advertised length; extra
   * bytes will be left unread and should remain buffered by the transport layer for subsequent
   * protocol messages. The bucket contents can be revisited multiple times after this call
   * completes, allowing retryable hashing or manifest serialization without contacting the client
   * again.
   *
   * @param is input stream sourced from the client socket; must remain open for the entire copy.
   * @throws IOException if the underlying stream cannot supply the required bytes or on bucket
   *     write failures.
   */
  public void read(InputStream is) throws IOException {
    BucketTools.copyFrom(data, is, length);
  }

  /**
   * Writes the staged payload into the supplied {@link OutputStream} for manifest assembly.
   *
   * <p>The copy size equals {@link #bytesToRead()}, ensuring downstream consumers receive the same
   * bytes previously accepted via {@link #read(InputStream)}. Because the content lives inside a
   * {@link RandomAccessBucket}, multiple invocations remain safe and deterministic, which is useful
   * for hashing, network retransmissions, or persisting the directory to disk caches. The delegate
   * {@link BucketTools#copyTo(network.crypta.support.api.Bucket, OutputStream, long)} propagates
   * {@link IOException}s whenever the output stream backpressure prevents timely writes.
   *
   * @param os destination stream, typically a manifest serializer or archive builder output.
   * @throws IOException if the destination rejects bytes, closes prematurely, or experiences I/O
   *     errors during transfer.
   */
  public void write(OutputStream os) throws IOException {
    BucketTools.copyTo(data, os, length);
  }

  /**
   * Returns the {@link RandomAccessBucket} that backs this direct upload entry.
   *
   * <p>The bucket owns the entire payload exactly as supplied by the client and offers random
   * access semantics so higher layers can seek, read, or even duplicate ranges without restreaming
   * over the network. Callers should treat the reference as mutable state confined to the owning
   * request context; concurrently reading and writing from multiple threads risks violating
   * invariants maintained by the bucket implementation. The caller remains responsible for closing
   * or freeing the bucket when the directory upload completes, typically via the surrounding
   * manifest builder.
   *
   * @return non-null bucket handle storing the uploaded bytes until the request lifecycle ends.
   */
  @Override
  public RandomAccessBucket getData() {
    return data;
  }
}
