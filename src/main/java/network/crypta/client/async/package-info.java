/**
 * Asynchronous client layer for high‑level fetch and insert workflows.
 *
 * <p>This package contains the engines that execute user‑visible requests: fetching data by key,
 * inserting files or whole sites, tracking progress, and coordinating retries. A single logical
 * request often expands into many low‑level operations such as following redirects, verifying
 * checksums, fetching splitfile segments, or assembling container formats. Implementations model
 * these steps as state machines and collaborate with schedulers to make progress without blocking
 * callers. Requests can be persistent (restored across restarts) or transient (memory‑only).
 *
 * <p>The scheduler selects which unit of work to start next based on priority classes, fairness
 * across clients, and back‑off/cooldown policies. Key listeners map blocks offered by the network
 * back to active requests. USK utilities provide polling and insertion for updatable keys. Healing
 * utilities re‑queue incomplete segments so long‑running downloads recover from transient failures.
 * Persistence focuses on durability for complex requests while rebuilding global indexes on
 * startup.
 *
 * <p><strong>Notable components</strong>
 *
 * <ul>
 *   <li>High‑level request orchestration via {@link network.crypta.client.async.ClientRequester}
 *       and concrete getters such as {@link network.crypta.client.async.ClientGetter}.
 *   <li>State machines for gets ({@link network.crypta.client.async.ClientGetState}) and puts
 *       ({@link network.crypta.client.async.ClientPutState}). Fetchers include {@link
 *       network.crypta.client.async.SingleFileFetcher} and {@link
 *       network.crypta.client.async.SplitFileFetcher}; inserters include {@link
 *       network.crypta.client.async.SingleBlockInserter} and {@link
 *       network.crypta.client.async.SplitFileInserter}.
 *   <li>Scheduling primitives: {@link network.crypta.client.async.ClientRequestScheduler} and the
 *       selection tree in {@link network.crypta.client.async.ClientRequestSelector}. Block
 *       selection/back‑off helpers include {@link network.crypta.client.async.CooldownBlockChooser}
 *       and key mapping via {@link network.crypta.client.async.KeyListener} and {@link
 *       network.crypta.client.async.KeyListenerTracker}.
 *   <li>USK support: {@link network.crypta.client.async.USKManager}, {@link
 *       network.crypta.client.async.USKFetcher}, and {@link
 *       network.crypta.client.async.USKInserter}.
 *   <li>Healing and housekeeping: {@link network.crypta.client.async.HealingQueue} and related
 *       helpers keep long downloads moving by revisiting incomplete segments.
 *   <li>Durable request persistence: {@link network.crypta.client.async.ClientLayerPersister}
 *       checkpoints active work and resumes it after restarts.
 * </ul>
 *
 * <p><strong>Interactions</strong>
 *
 * <ul>
 *   <li>Uses node‑level request senders and failure tracking; see {@link
 *       network.crypta.node.FailureTable} for related back‑off decisions.
 *   <li>Exposes progress and lifecycle to client interfaces, including the FCP layer (for example,
 *       {@link network.crypta.clients.fcp.PersistentRequestClient}).
 * </ul>
 */
package network.crypta.client.async;
