package network.crypta.client;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ArchiveHandlerImpl implements ArchiveHandler, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(ArchiveHandlerImpl.class);

  @Serial private static final long serialVersionUID = 1L;

  static {
  }

  private final FreenetURI key;
  private boolean forceRefetchArchive;
  ARCHIVE_TYPE archiveType;
  COMPRESSOR_TYPE compressorType;

  ArchiveHandlerImpl(
      FreenetURI key,
      ARCHIVE_TYPE archiveType,
      COMPRESSOR_TYPE ctype,
      boolean forceRefetchArchive) {
    this.key = key;
    this.archiveType = archiveType;
    this.compressorType = ctype;
    this.forceRefetchArchive = forceRefetchArchive;
  }

  @Override
  public Bucket get(String internalName, ArchiveContext archiveContext, ArchiveManager manager)
      throws ArchiveFailureException,
          ArchiveRestartException,
          MetadataParseException,
          FetchException {

    if (forceRefetchArchive) return null;

    Bucket data;

    // Fetch from cache
    if (LOG.isDebugEnabled()) LOG.debug("Checking cache: " + key + ' ' + internalName);
    if ((data = manager.getCached(key, internalName)) != null) {
      return data;
    }

    return null;
  }

  @Override
  public Bucket getMetadata(ArchiveContext archiveContext, ArchiveManager manager)
      throws ArchiveFailureException,
          ArchiveRestartException,
          MetadataParseException,
          FetchException {
    return get(".metadata", archiveContext, manager);
  }

  @Override
  public void extractToCache(
      Bucket bucket,
      ArchiveContext actx,
      String element,
      ArchiveExtractCallback callback,
      ArchiveManager manager,
      ClientContext context)
      throws ArchiveFailureException, ArchiveRestartException {
    forceRefetchArchive = false; // now we don't need to force refetch any more
    ArchiveStoreContext ctx = manager.makeContext(key, archiveType, compressorType, false);
    manager.extractToCache(
        key, archiveType, compressorType, bucket, actx, ctx, element, callback, context);
  }

  @Override
  public ARCHIVE_TYPE getArchiveType() {
    return archiveType;
  }

  public COMPRESSOR_TYPE getCompressorType() {
    return compressorType;
  }

  @Override
  public FreenetURI getKey() {
    return key;
  }

  @Override
  public ArchiveHandler cloneHandler() {
    return new ArchiveHandlerImpl(key, archiveType, compressorType, forceRefetchArchive);
  }
}
