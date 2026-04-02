package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.support.api.Bucket;

/**
 * Represents data-discovery and storage-target metadata captured for a download request.
 *
 * <p>This record bundles the request's data-related status values so they can be passed as a single
 * object when building a {@link DownloadRequestStatus} or rendering an FCP status reply. Callers
 * typically construct it alongside other snapshot bundles at the moment a status response is
 * prepared. The record does not validate or normalize its inputs; it simply preserves whatever
 * values the request has recorded at that point in time.
 *
 * <p>All components are stored verbatim. The {@link File} and {@link Bucket} references are not
 * copied, and no existence or lifecycle checks are performed. Thread-safety therefore depends on
 * how those referenced objects are shared, and callers should treat them as read-only while the
 * snapshot is in use by downstream encoders.
 *
 * <ul>
 *   <li>Captures discovered MIME type and data length in bytes.
 *   <li>Records a destination file for disk-based returns, if applicable.
 *   <li>Holds a bucket reference for in-memory or shadowed results.
 * </ul>
 *
 * @param foundDataMimeType MIME type hint for the data, or {@code null} if unknown
 * @param foundDataLength data length recorded for the request, in bytes when known
 * @param destinationFile destination file for disk requests, or {@code null} for in-memory data
 * @param dataBucket bucket containing result data, or {@code null} when not yet available
 * @see DownloadRequestStatus
 * @see DownloadRequestStatusDetails
 */
public record DownloadDataSnapshot(
    String foundDataMimeType, long foundDataLength, File destinationFile, Bucket dataBucket) {}
