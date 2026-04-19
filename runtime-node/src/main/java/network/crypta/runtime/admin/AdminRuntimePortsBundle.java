package network.crypta.runtime.admin;

import network.crypta.runtime.spi.AlertFeedPort;
import network.crypta.runtime.spi.AlertMutationPort;
import network.crypta.runtime.spi.ConnectionsPagePort;
import network.crypta.runtime.spi.ConnectionsSupportPort;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.DiagnosticPort;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.PageChromePort;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.StatisticsPort;
import network.crypta.runtime.spi.ToadletSymlinkPort;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;

/**
 * Groups the admin and page-oriented runtime SPI adapters owned by this package.
 *
 * <p>This record is the package-local handoff between {@link AdminRuntimePortsFactory} and {@link
 * network.crypta.runtime.core.LegacyRuntimePorts}. It lets the admin adapter cluster move together
 * without forcing the runtime-core nucleus to know which concrete classes implement the various
 * page, queue, and welcome flows. Callers typically create one bundle during runtime-port assembly
 * and then keep the individual port references in longer-lived wiring objects.
 *
 * <p>The record is immutable, but the contained ports are still live adapters over the mutable
 * daemon state. Holding a bundle does not snapshot node data, queue state, or welcome-page values.
 * It only preserves a stable set of adapter instances, so the surrounding wiring can pass them
 * around as one explicit ownership boundary.
 *
 * @param connectionsPage adapter that renders detached connections-page snapshots for admin pages
 * @param connectionsSupport adapter that exposes installer and peer-offer helpers for connections
 *     UI
 * @param darknetConnections adapter that resolves detached darknet friend actions against live
 *     peers
 * @param darknetMessaging adapter that sends detached darknet messages and file offers on demand
 * @param alertFeed adapter that exposes detached alert snapshots for admin-facing pages
 * @param alertMutation adapter that dismisses alerts by detached id
 * @param diagnostic adapter that exports detached diagnostic and report-oriented admin snapshots
 * @param pageChrome adapter that exposes shared page-shell status for admin toadlets and page maker
 * @param queueCompletion adapter that serves queue-completion exports and completion-oriented
 *     actions
 * @param queuePage adapter that renders detached queue-page snapshots and key-list exports
 * @param queueDownload adapter that performs queue download mutations through detached inputs
 * @param queueInsert adapter that performs queue insert mutations through detached inputs
 * @param queueMutation adapter that applies generic queue item mutation and removal operations
 * @param queueSupport adapter that exposes queue availability, persistence state, and panic helpers
 * @param statistics adapter that renders detached statistics-page snapshots for the admin UI
 * @param firstTimeWizard adapter that exports and applies first-time-wizard detached state
 * @param toadletSymlinks adapter that persists detached symlink configuration for admin toadlets
 * @param welcomePage adapter that exports detached welcome-page read state and log excerpts
 * @param welcomeAction adapter that applies detached welcome-page action and bandwidth submissions
 */
public record AdminRuntimePortsBundle(
    ConnectionsPagePort connectionsPage,
    ConnectionsSupportPort connectionsSupport,
    DarknetConnectionsPort darknetConnections,
    DarknetMessagingPort darknetMessaging,
    AlertFeedPort alertFeed,
    AlertMutationPort alertMutation,
    DiagnosticPort diagnostic,
    PageChromePort pageChrome,
    QueueCompletionPort queueCompletion,
    QueuePagePort queuePage,
    QueueDownloadPort queueDownload,
    QueueInsertPort queueInsert,
    QueueMutationPort queueMutation,
    QueueSupportPort queueSupport,
    StatisticsPort statistics,
    FirstTimeWizardPort firstTimeWizard,
    ToadletSymlinkPort toadletSymlinks,
    WelcomePagePort welcomePage,
    WelcomeActionPort welcomeAction) {}
