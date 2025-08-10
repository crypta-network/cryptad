package network.crypta.client;

import network.crypta.client.ArchiveManager.ARCHIVE_TYPE;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * @author toad
 * The public face (to Fetcher, for example) of ArchiveStoreContext.
 * Mostly has methods for fetching stuff, but SingleFileFetcher needs to be able
 * to download and then ask the ArchiveManager to extract it, so we include that 
 * functionality (extractToCache) too. Because ArchiveManager is not persistent,
 * we have to pass it in to each method.
 */
public interface ArchiveHandler {

	/**
	 * Get the metadata for this ZIP manifest, as a Bucket.
	 * THE RETURNED BUCKET WILL ALWAYS BE NON-PERSISTENT.
	 * @return The metadata as a Bucket, or null.
	 * @param manager The ArchiveManager.
	 * @throws FetchException If the container could not be fetched.
	 * @throws MetadataParseException If there was an error parsing intermediary metadata.
	 */
    Bucket getMetadata(ArchiveContext archiveContext,
                       ArchiveManager manager)
			throws ArchiveFailureException, ArchiveRestartException,
			MetadataParseException, FetchException;

	/**
	 * Get a file from this ZIP manifest, as a Bucket.
	 * If possible, read it from cache. If not, return null.
	 * THE RETURNED BUCKET WILL ALWAYS BE NON-PERSISTENT.
	 * @param inSplitZipManifest If true, indicates that the key points to a splitfile zip manifest,
	 * which means that we need to pass a flag to the fetcher to tell it to pretend it was a straight
	 * splitfile.
	 * @param manager The ArchiveManager.
	 * @throws FetchException 
	 * @throws MetadataParseException 
	 */
    Bucket get(String internalName,
               ArchiveContext archiveContext, ArchiveManager manager)
			throws ArchiveFailureException, ArchiveRestartException,
			MetadataParseException, FetchException;

	/**
	 * Get the archive type.
	 */
    ARCHIVE_TYPE getArchiveType();

	/**
	 * Get the key.
	 */
    FreenetURI getKey();
	
	/**
	 * Unpack a fetched archive to cache, and call the callback if there is one.
	 * @param bucket The downloaded data for the archive.
	 * @param actx The ArchiveContext.
	 * @param element The single element that the caller is especially interested in.
	 * @param callback Callback to be notified whether the content is available, and if so, fed the data.
	 * @param manager The ArchiveManager.
	 * @throws ArchiveFailureException
	 * @throws ArchiveRestartException
	 */
    void extractToCache(Bucket bucket, ArchiveContext actx, String element, ArchiveExtractCallback callback, ArchiveManager manager,
                        ClientContext context) throws ArchiveFailureException, ArchiveRestartException;

	ArchiveHandler cloneHandler();
	
}