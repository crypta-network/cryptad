package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Describes the payload source and metadata hints for a single-file put request.
 *
 * <p>The upload specification keeps the original filename, optional content type, bucket handle,
 * redirect target, and output filename together so callers can pass them as a single unit when
 * constructing {@link ClientPut} instances.
 *
 * @param uploadFromType source of the upload bytes (direct, disk, or redirect)
 * @param origFilename original filesystem filename when uploading from disk; may be {@code null}
 * @param contentType MIME type override for the upload; may be {@code null}
 * @param data bucket containing upload data or {@code null} for redirects
 * @param redirectTarget target URI for redirect uploads; may be {@code null}
 * @param targetFilename filename hint to store in metadata; may be {@code null}
 * @param binaryBlob whether the insert is an opaque binary blob with no metadata
 */
public record ClientPutUpload(
    UploadFrom uploadFromType,
    File origFilename,
    String contentType,
    RandomAccessBucket data,
    FreenetURI redirectTarget,
    String targetFilename,
    boolean binaryBlob) {}
