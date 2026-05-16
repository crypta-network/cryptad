package network.crypta.platform.api.queue;

import network.crypta.runtime.spi.QueueUploadedFile;

/**
 * Result of preparing one app-generated document for queue insertion.
 *
 * <p>The uploaded-file abstraction intentionally keeps generated document bytes inside server-side
 * queue code. Public Platform API responses use the fixed redacted source-path value instead of
 * exposing a local filesystem location.
 *
 * <p>The app-document route has two audiences after validation. The queue insert port needs a
 * replayable upload source so it can copy bytes into the daemon's persistent insert storage. The
 * browser caller needs only a creation summary, and that summary must not reveal whether the
 * implementation used memory, a temporary file, or another server-owned staging mechanism. This
 * record carries both views without giving request input any authority over local paths.
 *
 * @param upload generated document upload supplied to the queue insert port for trusted copying
 * @param publicSourcePath fixed redacted source-path placeholder used in API responses
 */
record AppGeneratedDocumentStagingResult(QueueUploadedFile upload, String publicSourcePath) {}
