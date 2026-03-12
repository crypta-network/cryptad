package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.NullOutputStream;

/**
 * Base class for FCP messages that carry a trailing binary data section in addition to their
 * SimpleFieldSet-style header fields.
 *
 * <p>The data payload is stored in a {@link Bucket} referenced by {@link #bucket}. When a message
 * is read from the network, {@link #readFrom(InputStream, BucketFactory, FCPServer)} allocates a
 * suitable bucket via {@link #createBucket(BucketFactory, long, FCPServer)} and streams the
 * trailing bytes into it. When a message is written, {@link #writeData(OutputStream)} copies the
 * previously attached bucket contents to the output stream.
 *
 * <p>Subclasses typically override {@link #dataLength()}, {@link #getIdentifier()}, and {@link
 * #isGlobal()} to describe the protocol-level semantics of the message and the expected payload
 * size. Instances are created per message, are mutable, and perform no internal synchronization;
 * callers should therefore confine each instance to a single connection-handling thread.
 *
 * <ul>
 *   <li>Messages that originate from a client normally use a {@link RandomAccessBucket} created by
 *       this class to allow later insertion into node storage.
 *   <li>Messages sent from the node to a client may wrap an arbitrary {@link Bucket} that does not
 *       necessarily support random access.
 * </ul>
 *
 * @see BaseDataCarryingMessage
 * @see MultipleDataCarryingMessage
 */
public abstract class DataCarryingMessage extends BaseDataCarryingMessage {

  /**
   * Backing storage for the binary payload associated with this message.
   *
   * <p>If this is a message received from a client, the bucket is created by {@link
   * #createBucket(BucketFactory, long, FCPServer)} and will normally be a {@link
   * RandomAccessBucket} suitable for insertion into persistent storage. For messages sent to a
   * client, the bucket may be any implementation supplied by the caller and is not required to
   * support random access.
   */
  protected Bucket bucket;

  /**
   * Create a {@link RandomAccessBucket} for storing the trailing payload of this message.
   *
   * @param bf the {@link BucketFactory} used to allocate the underlying storage for the payload;
   *     must be able to create buckets of the requested size
   * @param length the number of bytes that will be written into the returned bucket; usually the
   *     value reported by {@link #dataLength()}
   * @param server the FCP server context; overriding implementations may consult it to select a
   *     persistent or transient bucket factory as appropriate
   * @return a new {@link RandomAccessBucket} whose capacity is sufficient for the requested length;
   *     the caller is responsible for eventually freeing it
   * @throws IOException if the underlying storage cannot be allocated or another I/O problem is
   *     detected while preparing the bucket
   * @throws PersistenceDisabledException if persistence is disabled and a persistent bucket would
   *     be required; typically thrown by overrides that use persistent storage
   */
  RandomAccessBucket createBucket(BucketFactory bf, long length, FCPServer server)
      throws IOException, PersistenceDisabledException {
    return bf.makeBucket(length);
  }

  abstract String getIdentifier();

  abstract boolean isGlobal();

  /**
   * Indicates whether {@link #bucket} should be freed automatically after this message has been
   * written to an output stream.
   *
   * <p>When this flag is {@code true}, {@link #writeData(OutputStream)} will invoke {@link
   * Bucket#free()} once the payload has been copied. This is intended for transient buckets that
   * are only needed while sending the message and must not remain referenced afterward.
   */
  protected boolean freeOnSent;

  /**
   * Request that the payload bucket be freed automatically after the message has been written.
   *
   * <p>This is a convenience for callers that attach a transient bucket and want to ensure it is
   * released as soon as the corresponding network write completes. It only affects subsequent calls
   * to {@link #writeData(OutputStream)} and has no impact on how the payload is read.
   */
  void setFreeOnSent() {
    freeOnSent = true;
  }

  /**
   * Read the trailing payload bytes for this message from the given input stream.
   *
   * <p>The number of bytes to read is determined by {@link #dataLength()}. If that method returns a
   * negative value, no payload is read. If it returns zero, {@link #bucket} is set to a {@link
   * NullBucket}. Otherwise, this method allocates a {@link RandomAccessBucket} using {@link
   * #createBucket(BucketFactory, long, FCPServer)}, streams the requested number of bytes into it,
   * and stores it in {@link #bucket}.
   *
   * @param is the input stream providing the payload bytes; it must contain at least {@link
   *     #dataLength()} readable bytes when this method is invoked
   * @param bf the {@link BucketFactory} used to allocate the storage for the payload when data is
   *     present; the implementation may choose between different bucket types
   * @param server the FCP server context associated with this connection; passed through to {@link
   *     #createBucket(BucketFactory, long, FCPServer)} so subclasses can make persistence decisions
   * @throws IOException if an I/O error occurs while allocating the bucket or copying bytes from
   *     the input stream into the bucket
   * @throws MessageInvalidException if the payload cannot be stored, for example because
   *     persistence is disabled or an internal error occurs while creating the bucket
   */
  @Override
  public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException {
    long len = dataLength();
    if (len < 0) return;
    if (len == 0) {
      bucket = new NullBucket();
      return;
    }
    RandomAccessBucket tempBucket;
    try {
      tempBucket = createBucket(bf, len, server);
    } catch (IOException e) {
      FileUtil.copy(is, new NullOutputStream(), len);
      throw new MessageInvalidException(
          ProtocolErrorMessage.INTERNAL_ERROR, e.toString(), getIdentifier(), isGlobal());
    } catch (PersistenceDisabledException _) {
      FileUtil.copy(is, new NullOutputStream(), len);
      throw new MessageInvalidException(
          ProtocolErrorMessage.PERSISTENCE_DISABLED, null, getIdentifier(), isGlobal());
    }
    BucketTools.copyFrom(tempBucket, is, len);
    this.bucket = tempBucket;
  }

  /**
   * Write the trailing payload bytes for this message to the given output stream.
   *
   * <p>If {@link #dataLength()} returns a positive value, this method copies exactly that many
   * bytes from {@link #bucket} to the supplied stream. When {@link #freeOnSent} is {@code true},
   * the bucket is freed by calling {@link Bucket#free()} after the copy completes. If the data
   * length is zero or negative, no bytes are written and the bucket is left unchanged.
   *
   * @param os the output stream that will receive the payload data; the caller is responsible for
   *     flushing and closing the stream after the message has been fully written
   * @throws IOException if an I/O error occurs while reading from the bucket or writing to the
   *     output stream
   */
  @Override
  protected void writeData(OutputStream os) throws IOException {
    long len = dataLength();
    if (len > 0) BucketTools.copyTo(bucket, os, len);
    if (freeOnSent) bucket.free(); // Always transient so no removeFrom() needed.
  }

  @Override
  String getEndString() {
    return "Data";
  }

  /**
   * Return the payload bucket as a {@link RandomAccessBucket} for further processing.
   *
   * <p>This accessor is intended for code that handles messages received from a client, where the
   * bucket was created by {@link #createBucket(BucketFactory, long, FCPServer)} and therefore
   * supports random access. Callers that invoke this method for messages sent to a client must
   * ensure that the bucket they attached is actually a {@link RandomAccessBucket}.
   *
   * @return the underlying payload bucket cast to {@link RandomAccessBucket}; callers should
   *     typically assume this is non-{@code null} only after a successful {@link #readFrom} call
   *     has populated the bucket
   */
  public RandomAccessBucket getRandomAccessBucket() {
    return (RandomAccessBucket) bucket;
  }
}
