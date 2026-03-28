package network.crypta.runtime.endpoints.fcp;

import java.util.Objects;
import network.crypta.clients.fcp.BookmarkFeed;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FeedMessage;
import network.crypta.clients.fcp.N2NFeedMessageParams;
import network.crypta.clients.fcp.TextFeedMessage;
import network.crypta.clients.fcp.URIFeedMessage;
import network.crypta.runtime.alerts.feed.BasicUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.BookmarkUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.NodeToNodeFeedMetadata;
import network.crypta.runtime.alerts.feed.TextUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.UriUserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.UserAlertFeedEvent;

/**
 * Converts runtime-owned alert feed events into concrete FCP feed message instances.
 *
 * <p>This factory is the narrow bridge between the transport-neutral alert seam in {@code
 * network.crypta.runtime.alerts.feed} and the long-standing FCP message classes under {@code
 * network.crypta.clients.fcp}. Its main job is to recreate the same message kinds, header fields,
 * bucket payloads, and node-to-node metadata that the old direct alert implementations emitted
 * before the seam was introduced.
 *
 * <p>The factory is stateless and thread-safe. Callers typically invoke {@link #create} immediately
 * before sending a message on an FCP connection. Unsupported event types fail fast with {@link
 * IllegalArgumentException} so new runtime event shapes do not silently disappear on the protocol
 * boundary.
 *
 * @see FcpUserAlertFeedSubscriber
 * @see UserAlertFeedEvent
 */
public final class FcpUserAlertFeedMessageFactory {
  private FcpUserAlertFeedMessageFactory() {}

  /**
   * Converts one runtime-owned feed event into the matching concrete FCP message type.
   *
   * <p>The mapping is shape-based and preserves legacy behavior. Basic alerts become {@link
   * FeedMessage}, bookmark recommendations become {@link BookmarkFeed}, URI announcements become
   * {@link URIFeedMessage}, and node-to-node text messages become {@link TextFeedMessage}. The
   * method does not mutate the supplied event and allocates a fresh FCP message instance for each
   * invocation.
   *
   * @param event immutable runtime-owned feed event snapshot to encode for FCP delivery
   * @return a new FCP message instance whose fields and payload layout match the event shape
   * @throws NullPointerException if {@code event} is {@code null}
   * @throws IllegalArgumentException if the event type is not one of the supported runtime feed
   *     variants
   */
  public static FCPMessage create(UserAlertFeedEvent event) {
    Objects.requireNonNull(event, "event");
    return switch (event) {
      case BookmarkUserAlertFeedEvent bookmarkEvent -> createBookmarkFeed(bookmarkEvent);
      case TextUserAlertFeedEvent textEvent -> createTextFeed(textEvent);
      case UriUserAlertFeedEvent uriEvent -> createUriFeed(uriEvent);
      case BasicUserAlertFeedEvent basicEvent -> createBasicFeed(basicEvent);
      default ->
          throw new IllegalArgumentException(
              "Unsupported user-alert feed event type: " + event.getClass());
    };
  }

  private static FeedMessage createBasicFeed(BasicUserAlertFeedEvent event) {
    return new FeedMessage(
        event.header(),
        event.shortText(),
        event.text(),
        event.priorityClass(),
        event.updatedTime());
  }

  private static BookmarkFeed createBookmarkFeed(BookmarkUserAlertFeedEvent event) {
    return new BookmarkFeed(
        createNodeToNodeParams(
            event.header(),
            event.shortText(),
            event.text(),
            event.priorityClass(),
            event.updatedTime(),
            event.metadata()),
        event.bookmarkTitle(),
        event.uri(),
        event.description(),
        event.hasActiveLink());
  }

  private static URIFeedMessage createUriFeed(UriUserAlertFeedEvent event) {
    return new URIFeedMessage(
        createNodeToNodeParams(
            event.header(),
            event.shortText(),
            event.text(),
            event.priorityClass(),
            event.updatedTime(),
            event.metadata()),
        event.uri(),
        event.description());
  }

  private static TextFeedMessage createTextFeed(TextUserAlertFeedEvent event) {
    return new TextFeedMessage(
        createNodeToNodeParams(
            event.header(),
            event.shortText(),
            event.text(),
            event.priorityClass(),
            event.updatedTime(),
            event.metadata()),
        event.messageText());
  }

  private static N2NFeedMessageParams createNodeToNodeParams(
      String header,
      String shortText,
      String text,
      short priorityClass,
      long updatedTime,
      NodeToNodeFeedMetadata metadata) {
    return new N2NFeedMessageParams(
        header,
        shortText,
        text,
        priorityClass,
        updatedTime,
        metadata.sourceNodeName(),
        metadata.composed(),
        metadata.sent(),
        metadata.received());
  }
}
