package network.crypta.clients.fcp;

import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.support.api.Bucket;

/**
 * Captures outcome details for a completed or in-flight download.
 *
 * <p>This bundle mirrors the fields that are updated when a download reaches a terminal state or
 * when cached status entries are reconstructed.
 *
 * @param dataSize size of the retrieved data in bytes.
 * @param mimeType MIME type hint for the payload.
 * @param failureCode failure classification, if any.
 * @param failureReasonShort concise failure reason for summaries.
 * @param failureReasonLong verbose failure reason for logs.
 * @param dataShadow shadow bucket holding the retrieved data, if available.
 * @param filterData whether the data was filtered.
 */
public record DownloadOutcomeInfo(
    long dataSize,
    String mimeType,
    FetchExceptionMode failureCode,
    String failureReasonShort,
    String failureReasonLong,
    Bucket dataShadow,
    boolean filterData) {}
