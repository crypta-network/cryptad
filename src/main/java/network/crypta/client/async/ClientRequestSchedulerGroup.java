package network.crypta.client.async;

/**
 * A minimal marker interface that groups related client operations for the request scheduler.
 *
 * <p>Instances represent the unit that the scheduler considers when allocating opportunities to do
 * work. In the simple case of fetching or inserting a single file, the {@link ClientRequester}
 * itself commonly acts as the scheduler group. More complex workflows (for example, multi-file site
 * inserts) may subdivide into several low-level requests while still sharing the same logical group
 * for fairness and accounting. Conceptually, this is the level immediately below a {@link
 * network.crypta.node.RequestClient} in the selection tree and typically corresponds to a
 * high-level request issued by a client.
 *
 * <p>Life cycle and identity: Implementations should provide a stable identity for the duration of
 * the grouped activity so the scheduler can apply round‑robin or quota policies consistently. This
 * interface intentionally defines no methods or ordering constraints; concrete types control their
 * own mutability and are free to attach whatever state they require. Concurrency characteristics
 * therefore depend on the implementing class; callers must consult that documentation for
 * thread‑safety guarantees.
 *
 * <p>Typical usage is indirect: a {@code SendableRequest} reports its scheduler group, and the
 * {@link ClientRequestSelector} organizes the selection arrays along those boundaries to balance
 * work across groups before choosing specific items.
 *
 * <ul>
 *   <li>Responsibility: define a logical scheduling bucket for a set of related operations.
 *   <li>Scope: one high‑level request (often a single file or site insert).
 *   <li>Behavior: no methods; used purely as a type to partition scheduling.
 * </ul>
 *
 * @see ClientRequester
 * @see ClientRequestSelector
 * @see network.crypta.node.SendableRequest
 * @see network.crypta.node.RequestClient
 */
public interface ClientRequestSchedulerGroup {}
