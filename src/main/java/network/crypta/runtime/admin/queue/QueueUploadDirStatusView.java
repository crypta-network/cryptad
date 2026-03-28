package network.crypta.runtime.admin.queue;

/**
 * Marks a runtime-owned view of a queued directory-upload request.
 *
 * <p>This interface exists so runtime-admin can tell directory uploads apart from file uploads
 * without importing backend-specific status classes. The distinction matters because the legacy
 * cleanup path only removes succeeding file uploads automatically; directory uploads remain visible
 * unless a caller removes them explicitly through another queue action.
 */
public interface QueueUploadDirStatusView extends QueueRequestStatusView {}
