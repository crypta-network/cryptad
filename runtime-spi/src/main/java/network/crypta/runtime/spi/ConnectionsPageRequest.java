package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Immutable request parameters for one detached legacy connections-page render.
 *
 * <p>The legacy connections area is still page-oriented rather than API-oriented, so callers pass
 * the small set of request flags that influence how the historical page is assembled: which peer
 * set to read, whether advanced sections are enabled, whether the message-type drill-down is
 * active, and how the peer rows should be sorted. The record remains JDK-only and does not expose
 * HTTP or daemon-owned types.
 *
 * @param kind which legacy connections page should be rendered?
 * @param advancedMode whether advanced-only sections and columns should be included
 * @param drawMessageTypes whether per-peer message-type rows should be included
 * @param sortBy requested sort key, or {@code null} to keep default ordering
 * @param reversed whether the selected sort should be inverted
 */
public record ConnectionsPageRequest(
    ConnectionsPageKind kind,
    boolean advancedMode,
    boolean drawMessageTypes,
    String sortBy,
    boolean reversed) {
  /**
   * Creates a detached connections-page render request.
   *
   * @throws NullPointerException if {@code kind} is {@code null}
   */
  public ConnectionsPageRequest {
    Objects.requireNonNull(kind, "kind");
  }
}
