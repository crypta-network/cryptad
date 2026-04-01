package network.crypta.runtime.alerts;

/**
 * Marker interface for user alerts that represent node‑to‑node messages.
 *
 * <p>Implementations of this interface identify alerts originating from, and intended for,
 * communication between two peers in the network. The marker is used by higher‑level routing and UI
 * components to categorize, filter, or render alerts differently from purely local notifications.
 * Typical implementations are small, immutable data holders that carry presentation details (for
 * example, a subject line, optional description text, or an identifier linking to a conversation or
 * transfer). The interface does not define methods or behavior; it provides a type cue only.
 *
 * <p>Thread‑safety and lifecycle semantics are determined by the concrete alert class. In common
 * usage, an alert is created, handed to an alert bus or controller, displayed to a user, and then
 * released once acknowledged or expired. Implementations should avoid storing heavyweight resources
 * and prefer referencing external state by stable identifiers when possible.
 *
 * <ul>
 *   <li>Purpose: categorize alerts that carry peer‑to‑peer messages.
 *   <li>Behavior: no API contract; presence is used for dispatching and UI decisions.
 *   <li>Scope: applies to any alert traveling over node‑to‑node communication paths.
 * </ul>
 *
 * @see AbstractUserAlert
 * @see AbstractNodeToNodeFileOfferUserAlert
 */
public interface NodeToNodeMessageUserAlert {}
