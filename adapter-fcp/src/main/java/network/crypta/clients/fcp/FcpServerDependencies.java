package network.crypta.clients.fcp;

import network.crypta.runtime.spi.RuntimePorts;

/**
 * Bootstrap dependency bundle required to construct an {@link FCPServer}.
 *
 * <p>This record carries the already-built runtime seams used by the server and its listeners. The
 * bundle is intentionally free of direct {@link network.crypta.node.NodeClientCore} access so
 * server construction can stay isolated from the broader daemon core once the support adapters are
 * created.
 *
 * @param runtimePorts runtime SPI bridge used by server-owned infrastructure
 * @param persistentRoot persistence root used to access global clients and caches
 * @param serverRuntimeSupport server-owned runtime seam for persistent ops and connection handling
 * @param messageRuntimeSupport residual message-path runtime seam
 * @param fetchRuntimeSupport GET/fetch runtime seam for server-owned request flows
 * @param messageFetchRuntimeSupport GET/fetch runtime seam for inbound message request flows
 * @param insertRuntimeSupport insert/USK runtime seam for server-owned request flows
 */
public record FcpServerDependencies(
    RuntimePorts runtimePorts,
    PersistentRequestRoot persistentRoot,
    FcpServerRuntimeSupport serverRuntimeSupport,
    FcpMessageRuntimeSupport messageRuntimeSupport,
    FcpFetchRuntimeSupport fetchRuntimeSupport,
    FcpFetchRuntimeSupport messageFetchRuntimeSupport,
    FcpInsertRuntimeSupport insertRuntimeSupport) {}
