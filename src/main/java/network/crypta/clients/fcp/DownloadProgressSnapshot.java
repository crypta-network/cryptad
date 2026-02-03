package network.crypta.clients.fcp;

/**
 * Parameter bundle describing cached progress and failure details for a download.
 *
 * @param progressPending last recorded progress message, or {@code null} if none
 * @param failedMessage cached failure message, or {@code null} when no failure is known
 */
public record DownloadProgressSnapshot(
    SimpleProgressMessage progressPending, GetFailedMessage failedMessage) {}
