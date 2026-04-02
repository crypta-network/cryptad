package network.crypta.clients.fcp;

import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;

/**
 * Parameter bundle describing upload-specific status metadata.
 *
 * <p>This record captures the URI and failure fields shared across upload status implementations.
 *
 * @param finalURI published URI if the upload has completed.
 * @param targetURI intended URI supplied by the client.
 * @param failureCode failure classification reported by the insert.
 * @param failureReasonShort concise failure reason.
 * @param failureReasonLong verbose failure reason.
 */
public record UploadRequestStatusDetails(
    FreenetURI finalURI,
    FreenetURI targetURI,
    InsertExceptionMode failureCode,
    String failureReasonShort,
    String failureReasonLong) {}
