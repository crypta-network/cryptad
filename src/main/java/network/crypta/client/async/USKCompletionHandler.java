package network.crypta.client.async;

import java.io.IOException;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.KeyDecodeException;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Handles data retention and callback completion for USK fetchers. */
final class USKCompletionHandler {
  private static final Logger LOG = LoggerFactory.getLogger(USKCompletionHandler.class);

  /** Last successfully fetched data bucket, retained when keepLastData is enabled. */
  private Bucket lastRequestData;

  /** Compression codec used for the last fetched data payload. */
  private short lastCompressionCodec;

  /** Whether the last fetched block represented metadata rather than raw data. */
  private boolean lastWasMetadata;

  private final boolean keepLastData;

  USKCompletionHandler(boolean keepLastData) {
    this.keepLastData = keepLastData;
  }

  boolean hasLastRequestData() {
    return lastRequestData != null;
  }

  short lastCompressionCodec() {
    return lastCompressionCodec;
  }

  boolean lastWasMetadata() {
    return lastWasMetadata;
  }

  void clearLastRequestData() {
    if (lastRequestData != null) {
      lastRequestData.free();
    }
    lastRequestData = null;
  }

  Bucket decodeBlockIfNeeded(
      boolean decode, ClientSSKBlock block, ClientContext context, ClientRequester parent) {
    if (!decode || block == null) return null;
    return ClientSSKBlockDecoder.decode(block, context, parent.persistent());
  }

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

  byte[] releaseLastDataBytes() {
    synchronized (this) {
      if (lastRequestData == null) return new byte[0];
      try {
        return BucketTools.toByteArray(lastRequestData);
      } catch (IOException e) {
        LOG.error("Unable to turn lastRequestData into byte[]: caught I/O exception: {}", e, e);
        return new byte[0];
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
        LOG.error("An IOE occured while decoding: {}", e.getMessage(), e);
        return null;
      }
    }
  }
}
