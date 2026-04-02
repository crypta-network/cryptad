package network.crypta.client.async;

import java.io.IOException;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.KeyDecodeException;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks the most recently decoded USK payload and exposes it to completion callbacks.
 *
 * <p>This helper is used by USK fetch coordination to retain metadata about the last successful
 * fetch and optionally hold on to the decoded data bucket. Callers feed decoded blocks or already
 * decoded byte arrays into this instance, then later query or release the retained data when a
 * fetcher completes. The handler is intentionally stateful: it keeps the last compression codec,
 * whether the last block was metadata, and an optional data bucket controlled by {@code
 * keepLastData}.
 *
 * <p>All state mutations are synchronized on the instance to allow concurrent fetch activity. The
 * class does not perform network I/O; it only records and releases data that has already been
 * decoded. Callers must treat returned buckets and byte arrays as owned by the caller after
 * retrieval.
 *
 * <ul>
 *   <li>Retain or discard decoded data depending on {@code keepLastData}.
 *   <li>Expose last-known codec and metadata flags for completion callbacks.
 *   <li>Release retained data safely when a fetcher terminates.
 * </ul>
 *
 * @see USKCompletionCoordinator
 * @see USKFetcher
 */
final class USKCompletionHandler {
  private static final Logger LOG = LoggerFactory.getLogger(USKCompletionHandler.class);

  /** Last successfully fetched data bucket, retained when keepLastData is enabled. */
  private Bucket lastRequestData;

  /** Compression codec used for the last fetched data payload. */
  private short lastCompressionCodec;

  /** Whether the last fetched block represented metadata rather than raw data. */
  private boolean lastWasMetadata;

  private final boolean keepLastData;

  /**
   * Creates a handler that may optionally retain the most recently decoded payload.
   *
   * <p>The {@code keepLastData} flag controls whether decoded data buckets are held so that
   * completion callbacks can access them later. The handler does not decode any data on its own
   * during construction; it only initializes the retention policy and starts with an empty state.
   *
   * @param keepLastData {@code true} to retain the last decoded bucket; {@code false} to discard
   *     decoded data after updating metadata flags and codec information.
   */
  USKCompletionHandler(boolean keepLastData) {
    this.keepLastData = keepLastData;
  }

  /**
   * Reports whether a retained data bucket is currently available.
   *
   * <p>The value reflects the last successful decoding that was retained. The result may change
   * after {@link #applyDecodedData(boolean, ClientSSKBlock, Bucket)} or {@link
   * #applyFoundDecodedData(boolean, boolean, short, byte[], ClientContext)} is called, or after
   * {@link #releaseLastDataBytes()} frees the stored bucket.
   *
   * @return {@code true} if a bucket is currently stored; {@code false} otherwise.
   */
  boolean hasLastRequestData() {
    synchronized (this) {
      return lastRequestData != null;
    }
  }

  /**
   * Returns the compression codec recorded for the most recently applied block.
   *
   * <p>The codec is updated when decoded data is applied or when metadata is applied from a found
   * edition. If no block has been applied yet, the value remains at the default zero value.
   *
   * @return the last compression codec recorded for a decoded block.
   */
  short lastCompressionCodec() {
    synchronized (this) {
      return lastCompressionCodec;
    }
  }

  /**
   * Returns whether the most recently applied block represented metadata.
   *
   * <p>This reflects the last known metadata flag from applied decoded data or from a found
   * edition. Callers should interpret it in tandem with {@link #lastCompressionCodec()} when
   * building completion callbacks.
   *
   * @return {@code true} if the last applied block was metadata; {@code false} otherwise.
   */
  boolean lastWasMetadata() {
    synchronized (this) {
      return lastWasMetadata;
    }
  }

  /**
   * Releases any retained data bucket and clears stored state.
   *
   * <p>This method frees the retained bucket if one exists and clears the handler reference so it
   * can be garbage collected. It does not modify codec or metadata flags, which are updated by
   * later calls to {@link #applyDecodedData(boolean, ClientSSKBlock, Bucket)}.
   */
  void clearLastRequestData() {
    synchronized (this) {
      if (lastRequestData != null) {
        lastRequestData.free();
      }
      lastRequestData = null;
    }
  }

  /**
   * Decodes the provided block into a data bucket when decoding is requested.
   *
   * <p>This method is a small adapter that checks the decode flag and the availability of the
   * block. If either condition is not met, it returns {@code null} without changing internal state.
   * When decoding is performed, the returned bucket is owned by the caller and may be retained or
   * freed based on {@link #applyDecodedData(boolean, ClientSSKBlock, Bucket)}.
   *
   * @param decode {@code true} to decode the provided block; {@code false} to skip decoding.
   * @param block the block to decode, or {@code null} when no block is available.
   * @param context client context used to get temporary bucket factories.
   * @param parent requester providing persistence information for bucket allocation.
   * @return a decoded data bucket, or {@code null} if decoding was skipped or failed.
   */
  Bucket decodeBlockIfNeeded(
      boolean decode, ClientSSKBlock block, ClientContext context, ClientRequester parent) {
    if (!decode || block == null) return null;
    return ClientSSKBlockDecoder.decode(block, context, parent.persistent());
  }

  /**
   * Applies decoded data and updates the recorded metadata and codec state.
   *
   * <p>The method is synchronized to serialize state updates. When decoding is disabled, it is a
   * no-op. If a block is supplied, the codec and metadata flags are taken from that block, and the
   * data bucket is either retained or freed based on {@code keepLastData}. If the block is {@code
   * null}, codec and metadata flags are reset and any retained bucket is cleared.
   *
   * @param decode {@code true} to apply the block information; {@code false} to skip updates.
   * @param block the decoded block, or {@code null} to clear codec and metadata state.
   * @param data the decoded data bucket, or {@code null} when no payload is available.
   */
  void applyDecodedData(boolean decode, ClientSSKBlock block, Bucket data) {
    synchronized (this) {
      if (!decode) return;
      if (block != null) {
        lastCompressionCodec = block.getCompressionCodec();
        lastWasMetadata = block.isMetadata();
        if (keepLastData) {
          if (lastRequestData != null) lastRequestData.free();
          lastRequestData = data;
        } else if (data != null) {
          data.free();
        }
      } else {
        lastCompressionCodec = -1;
        lastWasMetadata = false;
        lastRequestData = null;
      }
    }
  }

  /**
   * Applies already decoded data and records metadata/codec values.
   *
   * <p>This variant is used when a decoded byte array is already available, such as when data is
   * supplied by a higher-level cache. If {@code keepLastData} is enabled, the byte array is wrapped
   * into an immutable bucket for retention. If decoding is disabled, no changes are made.
   *
   * @param decode {@code true} to apply the provided metadata and data; {@code false} to skip.
   * @param metadata {@code true} when the payload represents metadata rather than raw data.
   * @param codec compression codec identifier associated with the decoded payload.
   * @param data decoded data bytes; must not be mutated by the caller after passing here.
   * @param context client context providing the temporary bucket factory for retention.
   */
  void applyFoundDecodedData(
      boolean decode, boolean metadata, short codec, byte[] data, ClientContext context) {
    synchronized (this) {
      if (!decode) return;
      lastCompressionCodec = codec;
      lastWasMetadata = metadata;
      if (keepLastData) {
        // Note: converting bucket to byte[] and back is inefficient
        if (lastRequestData != null) lastRequestData.free();
        try {
          lastRequestData = BucketTools.makeImmutableBucket(context.tempBucketFactory, data);
        } catch (IOException e) {
          LOG.error("Caught {}", e, e);
        }
      }
    }
  }

  /**
   * Releases retained data as a byte array and clears the stored bucket.
   *
   * <p>If no data is retained, this returns {@code null} to preserve the "no payload" signal used
   * by downstream callbacks. The caller owns the returned byte array. The retained bucket is always
   * freed, even if conversion fails, ensuring the handler does not retain buffers longer than
   * needed.
   *
   * @return the retained data bytes, or {@code null} when no data is stored
   */
  @SuppressWarnings("java:S1168")
  byte[] releaseLastDataBytes() {
    synchronized (this) {
      if (lastRequestData == null) return null;
      try {
        return BucketTools.toByteArray(lastRequestData);
      } catch (IOException e) {
        LOG.error("Unable to turn lastRequestData into byte[]: caught I/O exception: {}", e, e);
        return null;
      } finally {
        lastRequestData.free();
        lastRequestData = null;
      }
    }
  }

  private static final class ClientSSKBlockDecoder {
    private ClientSSKBlockDecoder() {}

    private static Bucket decode(ClientSSKBlock block, ClientContext context, boolean persistent) {
      try {
        return block.decode(context.getBucketFactory(persistent), 1025 /* it's an SSK */, true);
      } catch (KeyDecodeException _) {
        return null;
      } catch (IOException e) {
        LOG.error("Decode failed due to I/O error: {}", e.getMessage(), e);
        return null;
      }
    }
  }
}
