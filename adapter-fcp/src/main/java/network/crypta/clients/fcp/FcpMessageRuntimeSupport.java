package network.crypta.clients.fcp;

import java.io.IOException;
import java.net.URL;
import network.crypta.keys.FreenetURI;

/**
 * Narrow runtime support seam for residual message-level FCP operations.
 *
 * <p>This contract gives the remaining message handlers in {@code clients.fcp} a small, explicit
 * surface for runtime-dependent work that used to reach directly into {@link
 * network.crypta.node.NodeClientCore}. Typical callers get the adapter from {@link
 * FCPServer#messageRuntimeSupport()} and immediately delegate one operation such as peer lookup,
 * shutdown, or probe startup while keeping protocol branching in the message class itself.
 *
 * <p>The interface remains owned by the FCP package even though the remaining core-backed
 * implementation now lives under runtime bootstrap wiring. It is public only so that runtime-owned
 * adapters can implement it from outside {@code clients.fcp}. It is not part of {@code
 * runtime-spi}, and it is not intended to become a general daemon abstraction. Its job is narrower:
 * preserve existing node behavior while removing direct core dependencies from message-level
 * execution paths, so later refactors can adjust server bootstrap and configuration seams without
 * touching protocol handlers again. Peer lookup, probe execution, and AddPeer peer-reference
 * loading now use adapter-owned seam types, so the protocol package no longer imports concrete node
 * peer, probe, or client/fetch classes directly.
 *
 * <ul>
 *   <li>Exposes only the runtime actions still needed by residual message classes.
 *   <li>Leaves protocol validation, reply construction, and authorization with the message code.
 *   <li>Allows tests to substitute the runtime side of those operations without mocking the core.
 * </ul>
 *
 * @see FCPServer#messageRuntimeSupport()
 */
public interface FcpMessageRuntimeSupport {

  /**
   * Reads peer-reference text from a regular URL.
   *
   * <p>This operation exists so {@link AddPeer} can keep URL parsing, fallback policy, and protocol
   * error mapping in the adapter layer while delegating the concrete I/O to the runtime-backed
   * bridge. Implementations should preserve the historical newline-joining behavior and character
   * decoding used when reading noderef text from ordinary URLs.
   *
   * @param url absolute URL pointing to a textual peer reference document
   * @return mutable buffer containing the fetched peer-reference text
   * @throws IOException if opening or reading the URL fails
   */
  StringBuilder readPeerReferenceFromUrl(URL url) throws IOException;

  /**
   * Reads peer-reference text from a Crypta/Freenet URI using message-specified request policy.
   *
   * <p>Implementations should create and use the same short-lived high-level client behavior that
   * AddPeer historically received from the backing core for this fetch path. Fetch-level failures
   * for an otherwise valid URI are reported through {@link FcpPeerReferenceFetchException} so the
   * message layer can preserve its existing fallback-to-URL behavior, while I/O failures that occur
   * after a successful fetch continue to surface as {@link IOException}.
   *
   * @param uri Crypta/Freenet URI locating the remotely stored peer reference
   * @param priorityClass client priority class requested by the message handler
   * @param forceDontIgnoreStore whether explicit store-visibility behavior should be forced
   * @param forceMixedQueue whether mixed-queue behavior should be forced on the created client
   * @return mutable buffer containing the fetched peer-reference text
   * @throws IOException if the URI fetch succeeds but the returned data cannot be read fully
   * @throws FcpPeerReferenceFetchException if the URI is valid but the fetch itself fails
   */
  StringBuilder readPeerReferenceFromCryptaUri(
      FreenetURI uri, short priorityClass, boolean forceDontIgnoreStore, boolean forceMixedQueue)
      throws IOException, FcpPeerReferenceFetchException;

  /**
   * Enables or disables feed watching for a connection handler.
   *
   * <p>This hook toggles the handler's registration with the node-side alert or feed subsystem. The
   * message layer remains responsible for parsing the {@code Enabled} flag and deciding when to
   * call this method; the adapter only performs the runtime action. Implementations may treat the
   * call as idempotent if the handler is already in the requested state, matching the underlying
   * alert manager semantics.
   *
   * @param handler active FCP connection handler whose feed registration should change
   * @param enabled whether watch mode should be enabled for the supplied handler
   */
  void watchFeeds(FCPConnectionHandler handler, boolean enabled);

  /**
   * Requests a node shutdown with the supplied reason.
   *
   * <p>Callers invoke this only after message-level authorization and reply ordering have already
   * been handled. The adapter therefore performs the runtime shutdown action itself and should pass
   * the supplied reason through unchanged so daemon logs and lifecycle reporting continue to show
   * the same shutdown cause text as before the seam was introduced.
   *
   * @param reason shutdown reason passed through to the node lifecycle machinery
   */
  void shutdownNode(String reason);

  /**
   * Resolves a peer node by its FCP node identifier.
   *
   * <p>This lookup is used by message handlers that still need node-level peer routing decisions
   * but should no longer navigate from the server into the core and network objects directly. The
   * returned value tells the caller whether the identifier is unknown, refers to a non-darknet
   * peer, or yields a usable adapter-owned darknet peer handle.
   *
   * @param nodeIdentifier peer identifier supplied by the inbound message
   * @return adapter-owned lookup result describing whether the peer is unknown, non-darknet, or a
   *     darknet peer handle
   */
  FcpPeerLookupResult findPeer(String nodeIdentifier);

  /**
   * Starts a probe request using the live node network subsystem.
   *
   * <p>The adapter is responsible only for handing the already-validated probe request off to the
   * runtime. Message code remains responsible for access checks, UID generation, and translating
   * listener callbacks back into FCP replies. Implementations should begin the probe with the same
   * hop limit, UID, and probe type supplied by the caller, then forward completion and error events
   * to the provided listener using the runtime's normal asynchronous behavior.
   *
   * @param hopsToLive probe hop limit to submit to the node network
   * @param uid probe UID chosen by the caller for correlation and reply matching
   * @param probeType adapter-owned probe type to execute against the live network
   * @param listener adapter-owned callback listener that receives probe results and failures
   */
  void startProbe(byte hopsToLive, long uid, FcpProbeType probeType, FcpProbeListener listener);
}
