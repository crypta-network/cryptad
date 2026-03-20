package network.crypta.node.runtime;

import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Objects;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.PeerManager;
import network.crypta.runtime.spi.DarknetMessageSendStatus;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.DarknetPeerRequiredException;
import network.crypta.runtime.spi.DarknetUploadedFile;
import network.crypta.runtime.spi.UnknownPeerException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPUploadedFile;

/**
 * Adapts the legacy node-to-node message compose/send flow to the runtime SPI.
 *
 * <p>This bridge keeps the remaining live daemon peer lookup and send delegation inside the daemon
 * root module while exposing only detached identities, detached upload content, and detached
 * UI-level send statuses to the HTTP layer. It performs no policy changes of its own.
 *
 * <p>The adapter is intentionally thin. It resolves the detached peer identifier at the last
 * responsible moment, forwards attachment offers and text sends to the existing {@link
 * DarknetPeerNode} APIs, and maps daemon status integers into the compact {@link
 * DarknetMessageSendStatus} contract used by the HTTP page. Attachment adaptation is kept
 * request-scoped and read-only so the runtime SPI can stay detached from HTTP bucket
 * implementations.
 */
final class LegacyDarknetMessagingPort implements DarknetMessagingPort {
  /** Null-check label used for detached upload arguments and wrappers. */
  private static final String ARG_UPLOAD = "upload";

  /** Resolver that maps detached node identifiers to live darknet peers when a send begins. */
  private final LegacyDarknetPeerResolver peerResolver;

  /**
   * Creates a runtime-port bridge rooted at the current daemon instance.
   *
   * @param node live daemon root used only for request-scoped peer resolution
   */
  LegacyDarknetMessagingPort(Node node) {
    this.peerResolver = new LegacyDarknetPeerResolver(node);
  }

  /** {@inheritDoc} */
  @Override
  public DarknetMessageSendStatus sendText(String nodeIdentifier, String message)
      throws UnknownPeerException, DarknetPeerRequiredException {
    Objects.requireNonNull(message, "message");
    return mapSendStatus(peerResolver.resolveByIdentity(nodeIdentifier).sendTextFeed(message));
  }

  /** {@inheritDoc} */
  @Override
  public void sendFileOffer(String nodeIdentifier, File file, String messageHead)
      throws UnknownPeerException, DarknetPeerRequiredException, IOException {
    Objects.requireNonNull(file, "file");
    peerResolver.resolveByIdentity(nodeIdentifier).sendFileOffer(file, messageHead);
  }

  /** {@inheritDoc} */
  @Override
  public void sendUploadedFileOffer(
      String nodeIdentifier, DarknetUploadedFile upload, String messageHead)
      throws UnknownPeerException, DarknetPeerRequiredException, IOException {
    Objects.requireNonNull(upload, ARG_UPLOAD);
    DarknetPeerNode peer = peerResolver.resolveByIdentity(nodeIdentifier);
    peer.sendFileOffer(new StagedUploadedFile(upload), messageHead);
  }

  /** {@inheritDoc} */
  @Override
  public void recommendDownloads(String nodeIdentifier, List<String> uris, String description)
      throws UnknownPeerException, DarknetPeerRequiredException {
    Objects.requireNonNull(uris, "uris");
    DarknetPeerNode peer = peerResolver.resolveByIdentity(nodeIdentifier);
    for (String uri : uris) {
      peer.sendDownloadFeed(toFreenetUri(uri), description);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void shareBookmark(
      String nodeIdentifier, String uri, String name, String description, boolean hasActiveLink)
      throws UnknownPeerException, DarknetPeerRequiredException {
    Objects.requireNonNull(name, "name");
    peerResolver
        .resolveByIdentity(nodeIdentifier)
        .sendBookmarkFeed(toFreenetUri(uri), name, description, hasActiveLink);
  }

  /** {@inheritDoc} */
  @Override
  public DarknetMessageSendStatus sendComposedMessage(
      String nodeIdentifier,
      String message,
      File file,
      DarknetUploadedFile upload,
      String messageHead)
      throws UnknownPeerException, DarknetPeerRequiredException, IOException {
    Objects.requireNonNull(message, "message");
    DarknetPeerNode peer = peerResolver.resolveByIdentity(nodeIdentifier);
    if (file != null) {
      peer.sendFileOffer(file, messageHead);
    } else if (upload != null) {
      peer.sendFileOffer(new StagedUploadedFile(upload), messageHead);
    }
    return mapSendStatus(peer.sendTextFeed(message));
  }

  /**
   * Maps legacy daemon sends statuses into the smaller UI-facing delivery categories.
   *
   * @param legacyStatus daemon status constant returned by the legacy send path
   * @return detached delivery category that preserves the existing compose/send page buckets
   */
  private static DarknetMessageSendStatus mapSendStatus(int legacyStatus) {
    return switch (legacyStatus) {
      case PeerManager.PEER_NODE_STATUS_CONNECTED -> DarknetMessageSendStatus.SENT;
      case PeerManager.PEER_NODE_STATUS_ROUTING_BACKED_OFF -> DarknetMessageSendStatus.DELAYED;
      default -> DarknetMessageSendStatus.QUEUED;
    };
  }

  /**
   * Converts one validated detached URI string into the daemon URI type.
   *
   * <p>Queue recommendations validate URI syntax in the HTTP layer before crossing the runtime
   * boundary. A malformed value at this stage therefore indicates caller misuse or a regression in
   * that validation path, so the adapter reports it as an unchecked failure instead of widening the
   * SPI contract with queue-specific parsing errors.
   *
   * @param uri detached URI string supplied by the caller
   * @return daemon URI object ready for the legacy download-feed API
   */
  private static FreenetURI toFreenetUri(String uri) {
    Objects.requireNonNull(uri, "uri");
    try {
      return new FreenetURI(uri);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Malformed recommendation URI: " + uri, e);
    }
  }

  /**
   * Minimal uploaded-file view that lets the daemon reuse its existing HTTP-upload send path.
   *
   * <p>The wrapper is metadata-only apart from the detached upload reference. Each call to {@link
   * #getData()} returns a fresh read-only {@link Bucket} backed by the detached stream source.
   *
   * @param upload detached uploaded-file payload supplied through the runtime SPI
   */
  private record StagedUploadedFile(DarknetUploadedFile upload) implements HTTPUploadedFile {
    /**
     * Validates the detached upload wrapper.
     *
     * <p>The compact constructor stores no additional state beyond the record component.
     */
    private StagedUploadedFile {
      Objects.requireNonNull(upload, ARG_UPLOAD);
    }

    @Override
    public String getContentType() {
      return upload.contentType();
    }

    @Override
    public Bucket getData() {
      return new UploadStreamBucket(upload);
    }

    @Override
    public String getFilename() {
      return upload.filename();
    }
  }

  /**
   * Read-only bucket adapter that reopens a detached upload stream on demand.
   *
   * <p>The daemon's legacy file-offer path expects an {@link HTTPUploadedFile} backed by a {@link
   * Bucket}. This adapter satisfies that contract without reintroducing HTTP-layer bucket types
   * into the SPI or holding on to a single mutable stream instance between reads.
   */
  @SuppressWarnings("ClassCanBeRecord")
  private static final class UploadStreamBucket implements Bucket {
    /** Detached upload payload whose bytes are exposed through reopened input streams. */
    private final DarknetUploadedFile upload;

    /**
     * Creates one read-only bucket view for a detached upload payload.
     *
     * @param upload detached upload that can reopen its stream contents on demand
     */
    private UploadStreamBucket(DarknetUploadedFile upload) {
      this.upload = Objects.requireNonNull(upload, ARG_UPLOAD);
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      throw new IOException("UploadStreamBucket is read-only");
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() throws IOException {
      throw new IOException("UploadStreamBucket is read-only");
    }

    @Override
    public InputStream getInputStream() throws IOException {
      return upload.openStream();
    }

    @Override
    public InputStream getInputStreamUnbuffered() throws IOException {
      return upload.openStream();
    }

    @Override
    public String getName() {
      return "Uploaded N2NTM file: " + upload.filename();
    }

    @Override
    public long size() {
      return upload.size();
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }

    @Override
    public void setReadOnly() {
      // Always read-only.
    }

    @Override
    public void free() {
      // No resources are retained between stream openings.
    }

    @Override
    public Bucket createShadow() {
      return new UploadStreamBucket(upload);
    }

    @Override
    public void onResume(ClientContext context) {
      // Request-scoped upload streams do not participate in resume.
    }

    @Override
    public void storeTo(DataOutputStream dos) {
      throw new UnsupportedOperationException();
    }
  }
}
