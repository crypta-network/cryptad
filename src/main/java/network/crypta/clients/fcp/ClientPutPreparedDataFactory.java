package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Prepares upload buckets and redirect metadata for {@link ClientPut} requests.
 *
 * <p>This helper encapsulates redirect metadata creation and bucket resolution so the request class
 * can focus on lifecycle and scheduling behavior.
 */
final class ClientPutPreparedDataFactory {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutPreparedDataFactory.class);
  private static final String DATA_UPLOAD_LOG_TEMPLATE = "data = {}, uploadFrom = {}";

  private ClientPutPreparedDataFactory() {}

  static PreparedData prepareForPersistentUpload(
      ClientPutBase.UploadFrom uploadFrom,
      ClientMetadata metadata,
      RandomAccessBucket data,
      FreenetURI redirectTarget,
      NodeClientCore core,
      boolean persistentForever)
      throws MetadataUnresolvedException, IOException {
    if (uploadFrom == ClientPutBase.UploadFrom.REDIRECT) {
      Metadata redirectMetadata =
          new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, redirectTarget, metadata);
      RandomAccessBucket redirectData =
          redirectMetadata.toBucket(core.getClientContext().getBucketFactory(persistentForever));
      return new PreparedData(redirectData, true, redirectTarget);
    }
    return new PreparedData(data, false, null);
  }

  static PreparedData prepareForMessage(
      ClientPutMessage message,
      ClientMetadata metadata,
      FCPServer server,
      boolean persistentForever,
      ClientPutBase.UploadFrom uploadFrom,
      String identifier,
      boolean global)
      throws MessageInvalidException, IOException {
    RandomAccessBucket tempData = message.getRandomAccessBucket();
    if (LOG.isDebugEnabled()) LOG.debug(DATA_UPLOAD_LOG_TEMPLATE, tempData, uploadFrom);
    if (uploadFrom == ClientPutBase.UploadFrom.REDIRECT) {
      FreenetURI redirectTarget = message.redirectTarget;
      Metadata metadataDoc =
          new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, redirectTarget, metadata);
      try {
        RandomAccessBucket redirectData =
            metadataDoc.toBucket(
                server.getCore().getClientContext().getBucketFactory(persistentForever));
        return new PreparedData(redirectData, true, redirectTarget);
      } catch (MetadataUnresolvedException e) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INTERNAL_ERROR,
            "Impossible: metadata unresolved: " + e,
            identifier,
            global);
      }
    }
    return new PreparedData(tempData, false, null);
  }
}

record PreparedData(RandomAccessBucket bucket, boolean metadata, FreenetURI targetUri) {
  boolean isMetadata() {
    return metadata;
  }
}
