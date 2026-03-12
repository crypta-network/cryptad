package network.crypta.node.useralerts;

/**
 * A {@code UserEvent} represents a discrete, user‑visible occurrence emitted by the node, such as
 * announcing to the network or the completion of a client request. Implementations extend the
 * {@link UserAlert} contract and are routed to the user‑facing UI layers, which may group similar
 * events, allow dismissal, or persist lightweight state across restarts.
 *
 * <p>Typical usage involves constructing an implementation that carries minimal, immutable details
 * (for example, an identifier, a URI, or a byte size) and exposing a {@linkplain #getEventType()
 * type} that the UI can use to categorize the event. UIs and services may also use the {@link
 * Type#unregisterIndefinitely()} policy to decide whether dismissing one event should suppress
 * subsequent events of the same kind for the current user session.
 *
 * <p>Concurrency considerations: individual {@code UserEvent} instances are intended to be
 * read‑mostly once created. Implementations should prefer immutable fields and avoid expensive work
 * in accessors. The interface itself imposes no lifecycle constraints; producers may emit events on
 * arbitrary threads, and consumers should apply their own synchronization if required.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> identify the event category, provide concise text via
 *       {@link UserAlert}, and expose a suppression policy through {@link Type}.
 *   <li><strong>Notable behaviors:</strong> some event types are marked as unregister‑indefinite,
 *       which allows UIs to silence further notifications of the same type after dismissal.
 * </ul>
 *
 * @see UserAlert
 */
public interface UserEvent extends UserAlert {

  /**
   * Enumerates high‑level categories of user‑facing events emitted by the node and clients.
   * Categories help UI components group, summarize, and optionally suppress related notifications
   * without inspecting event payloads.
   */
  enum Type {
    /**
     * Events produced by the opennet announcing logic (for example, progress or temporary
     * disablement). These are often relevant only during bootstrap and may be silenced by users who
     * understand the background process.
     */
    ANNOUNCER(true),

    /**
     * Events indicating that a download (a client GET request) completed successfully. UIs
     * typically display the target name and size, and may provide quick navigation to the content.
     */
    GET_COMPLETED,

    /**
     * Events indicating that an upload (a client PUT request) completed successfully. These are
     * commonly grouped when multiple uploads finish around the same time.
     */
    PUT_COMPLETED,

    /**
     * Events indicating that a directory upload completed successfully. In addition to the target
     * URI, implementations often include a file count and aggregate size for display.
     */
    PUT_DIR_COMPLETED;

    private final boolean unregisterIndefinitely;

    /**
     * Creates a type with the specified post‑dismissal suppression behavior.
     *
     * @param unregisterIndefinitely whether dismissing a single event of this type should prevent
     *     subsequent events of the same type from being displayed for the remainder of the current
     *     session or until re‑enabled by the UI.
     */
    Type(boolean unregisterIndefinitely) {
      this.unregisterIndefinitely = unregisterIndefinitely;
    }

    /** Creates a type that does not enable indefinite suppression when dismissed. */
    Type() {
      unregisterIndefinitely = false;
    }

    /**
     * Indicates whether dismissing one event of this type should suppress further events of the
     * same type for the active session.
     *
     * @return {@code true} when a single dismissal requests indefinite unregistration of subsequent
     *     events of this type; {@code false} when each event remains independent and should
     *     continue to be shown.
     */
    public boolean unregisterIndefinitely() {
      return unregisterIndefinitely;
    }
  }

  /**
   * Returns the categorical {@link Type} of this event for UI grouping, filtering, and policy
   * decisions.
   *
   * <p>The returned value is stable for the lifetime of the event. Consumers should not assume any
   * particular frequency or ordering across types.
   *
   * <pre>{@code
   * // Example: derive a user-visible label from the event type
   * UserEvent evt = ...;
   * String label = switch (evt.getEventType()) {
   *   case GET_COMPLETED -> "Download finished";
   *   case PUT_COMPLETED -> "Upload finished";
   *   case PUT_DIR_COMPLETED -> "Directory upload finished";
   *   case ANNOUNCER -> "Node announcing";
   * };
   * }</pre>
   *
   * @return the immutable {@link Type} describing this event’s category; never {@code null} for a
   *     well‑formed implementation.
   */
  Type getEventType();
}
