package network.crypta.runtime.admin.queue;

/**
 * Marks a runtime-owned view of a queued file-upload request.
 *
 * <p>This interface intentionally adds no extra methods. Runtime-admin only needs to distinguish
 * file uploads from downloads and directory uploads when it applies the legacy finished-upload
 * cleanup rule. Keeping the type as a marker avoids pulling backend-specific upload details across
 * the queue seam while still preserving the existing category-specific behavior.
 */
public interface QueueUploadFileStatusView extends QueueRequestStatusView {}
