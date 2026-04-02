package network.crypta.clients.fcp;

/**
 * Configuration values used when constructing an {@link FCPServer}.
 *
 * <p>The record captures the bind and allowlist settings alongside runtime flags that affect FCP
 * request policies and outbound message queue behavior.
 *
 * @param bindTo textual bind address; use {@code 0.0.0.0} to listen on all interfaces.
 * @param allowedHosts comma-separated allowlist enforced for standard FCP sockets.
 * @param allowedHostsFullAccess allowlist used for privileged operations that bypass restrictions.
 * @param port TCP port number for the FCP listener.
 * @param enabled whether networked FCP should start.
 * @param assumeDownloadDDAAllowed flag to treat download DDA as preapproved.
 * @param assumeUploadDDAAllowed flag to treat upload DDA as preapproved.
 * @param neverDropAMessage whether outbound queues retain messages rather than dropping.
 * @param maxMessageQueueLength maximum messages buffered per connection before backpressure.
 */
public record FcpServerConfig(
    String bindTo,
    String allowedHosts,
    String allowedHostsFullAccess,
    int port,
    boolean enabled,
    boolean assumeDownloadDDAAllowed,
    boolean assumeUploadDDAAllowed,
    boolean neverDropAMessage,
    int maxMessageQueueLength) {}
