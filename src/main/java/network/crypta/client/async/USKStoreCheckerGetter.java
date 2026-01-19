package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.RequestClient;
import network.crypta.node.SendableGet;
import network.crypta.node.SendableRequestItem;

/**
 * A {@link SendableGet} that performs a local-only datastore presence probe for candidate USK
 * editions.
 *
 * <p>This getter is created by {@link USKStoreCheckCoordinator} when it wants to cheaply answer the
 * question "does the datastore already contain any likely next editions?" before attempting any
 * network fetch. It exposes a set of candidate {@link Key}s via {@link #listKeys()} and relies on
 * the surrounding request machinery to perform local checks only; it does not select a single key
 * to send, and it does not initiate network traffic itself.
 *
 * <p>Lifecycle-wise, the instance is intended to be single-shot: {@link #preRegister(ClientContext,
 * boolean)} delegates to {@link
 * USKStoreCheckCoordinator#preRegisterStoreChecker(USKStoreCheckerGetter,
 * USKStoreCheckCoordinator.USKStoreChecker, ClientContext, boolean)} and then permanently marks the
 * request as done so that later scheduling treats it as canceled. This keeps the store-check wiring
 * separate from {@code USKFetcher}'s polling logic, reducing coupling and making the probe behavior
 * explicit.
 *
 * <p>This class does not perform its own synchronization; it assumes the threading model used by
 * the request scheduler and the owning {@link USKStoreCheckCoordinator}.
 *
 * <ul>
 *   <li>Supplies candidate keys to probe via {@link #listKeys()}.
 *   <li>Delegates registration and accounting to the owning coordinator.
 *   <li>Cancels itself after registration to remain single-shot.
 * </ul>
 *
 * @see USKStoreCheckCoordinator
 * @see USKStoreCheckCoordinator.USKStoreChecker
 */
final class USKStoreCheckerGetter extends SendableGet {
  /** Coordinator for store-check lifecycle and callbacks. */
  private final transient USKStoreCheckCoordinator coordinator;

  /** Callbacks for fetcher-level state needed by the store check. */
  private final transient USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks;

  /** Candidate-key provider used to list likely USK edition datastore keys. */
  private final transient USKStoreCheckCoordinator.USKStoreChecker checker;

  /** Request the owner supplied at construction and passed to the superclass. */
  private final ClientRequester owner;

  /**
   * Tracks whether {@link #preRegister(ClientContext, boolean)} has run and this request is
   * therefore treated as canceled.
   */
  private boolean done;

  /**
   * Creates a new local-only store-check getter for a single USK polling pass.
   *
   * <p>The instance delegates most behavior to {@code coordinator} and {@code checker} and is
   * designed to be short-lived: once {@link #preRegister(ClientContext, boolean)} completes, the
   * getter marks itself done so that the scheduler stops considering it for further work.
   *
   * @param coordinator store-check coordinator for lifecycle events.
   * @param callbacks fetcher-level callbacks used for context and state.
   * @param owner request the owner used for scheduling and real-time flag.
   * @param checker candidate-key provider used for datastore probing decisions.
   */
  USKStoreCheckerGetter(
      USKStoreCheckCoordinator coordinator,
      USKStoreCheckCoordinator.USKStoreCheckCallbacks callbacks,
      ClientRequester owner,
      USKStoreCheckCoordinator.USKStoreChecker checker) {
    super(owner, owner.realTimeFlag());
    this.coordinator = coordinator;
    this.callbacks = callbacks;
    this.owner = owner;
    this.checker = checker;
  }

  /**
   * Returns the {@link FetchContext} used for this local store-check probe.
   *
   * <p>This implementation reuses the context configured on the owning {@link USKFetcher} and
   * returns the exact instance stored on the fetcher (no defensive copy). Sharing the context keeps
   * datastore behavior and fetch-policy settings consistent between the probe and any later USK
   * polling actions.
   *
   * @return the fetch context to use for store checks, shared with the owning fetcher.
   */
  @Override
  public FetchContext getContext() {
    return callbacks.fetcherContext();
  }

  /**
   * Returns the cooldown wakeup time for this request.
   *
   * <p>This getter is intended for a local-only presence probe and does not participate in
   * cooldown-based rescheduling. It therefore returns a sentinel value rather than calculating a
   * time based on {@code token} or {@code context}. Any retry timing or periodic polling is driven
   * by the owning {@link USKFetcher}, not by this helper request.
   *
   * @param token scheduler token for which cooldown is queried; may be null.
   * @param context client context associated with the request; must not be null.
   * @return {@code -1} to indicate no cooldown wakeup is scheduled by this getter.
   */
  @Override
  public long getCooldownWakeup(SendableRequestItem token, ClientContext context) {
    return -1;
  }

  /**
   * Returns a single key associated with the given token.
   *
   * <p>This store-check getter never resolves a per-token key and never constructs a network
   * request. Instead, it supplies all candidate keys up front via {@link #listKeys()}, allowing the
   * datastore probe to run without a network-sendable key selection step. Returning {@code null} is
   * intentional for this request type and indicates that there is no single key to fetch.
   *
   * @param token request item token that would normally map to a key; nullable.
   * @return {@code null}, because this getter does not map tokens to individual keys.
   */
  @Override
  public ClientKey getKey(SendableRequestItem token) {
    return null;
  }

  /**
   * Lists the candidate datastore keys to probe for likely USK editions.
   *
   * <p>The returned set is determined by {@link USKStoreCheckCoordinator.USKStoreChecker} and
   * represents the editions that the owning {@link USKFetcher} considers plausible next steps. The
   * scheduler uses this list for local store checking only; this getter never turns these keys into
   * network requests directly. This method returns the array provided by the checker without
   * copying it.
   *
   * @return an array of candidate {@link Key} instances to probe; may be empty.
   */
  @Override
  public Key[] listKeys() {
    return checker.getKeys();
  }

  /**
   * Handles a failure for this getter.
   *
   * <p>Failures are treated as non-fatal for the local store-check probe. The higher-level {@link
   * USKStoreCheckCoordinator} logic decides how to proceed (for example, whether to attempt a
   * network fetch), so this callback intentionally performs no action.
   *
   * <p>The parameters are accepted to satisfy the {@link SendableGet} contract but are otherwise
   * ignored.
   *
   * @param e low-level failure information; may be {@code null} depending on caller.
   * @param token request item token associated with the failure; may be null.
   * @param context client context associated with the request; must not be null.
   */
  @Override
  public void onFailure(LowLevelGetException e, SendableRequestItem token, ClientContext context) {
    // The store-check probe is best-effort; failures are handled by USKFetcher.
  }

  /**
   * Registers this getter with the scheduler, delegating the actual work to the owning fetcher.
   *
   * <p>This method forwards to {@link
   * USKStoreCheckCoordinator#preRegisterStoreChecker(USKStoreCheckerGetter,
   * USKStoreCheckCoordinator.USKStoreChecker, ClientContext, boolean)} and then marks the request
   * as done in a {@code finally} block so that {@link #isCancelled()} returns {@code true}
   * afterward. It is intended to run once per instance as part of a single store-check pass.
   *
   * @param context client context used during registration; must not be null.
   * @param toNetwork whether the scheduler is attempting a network registration; forwarded as-is.
   * @return {@code true} if the store-check registration succeeds; {@code false} otherwise.
   */
  @Override
  public boolean preRegister(ClientContext context, boolean toNetwork) {
    try {
      return coordinator.preRegisterStoreChecker(this, checker, context, toNetwork);
    } finally {
      done = true;
    }
  }

  /**
   * Selects a key to send based on the local-fetching state.
   *
   * <p>This getter never selects a network-sendable key. It exists only to drive local store
   * checking via {@link #listKeys()}, and the input parameters are unused. Returning {@code null}
   * prevents any attempt to schedule a network sending for this helper request. As a result, the
   * scheduler sees no sendable work from this getter.
   *
   * @param keys keys currently being fetched locally; ignored by this implementation.
   * @param context client context associated with the request; must not be null.
   * @return {@code null}, because this getter does not choose keys for sending.
   */
  @Override
  public SendableRequestItem chooseKey(KeysFetchingLocally keys, ClientContext context) {
    return null;
  }

  /**
   * Counts all keys considered by this getter for accounting purposes.
   *
   * <p>This count is used by the request machinery for progress and scheduling heuristics. The
   * value is delegated to the owning {@link USKFetcher} so it stays consistent with the fetcher's
   * current notion of candidate keys. This getter does not maintain independent key accounting.
   *
   * @param context client context used for accounting; must not be null.
   * @return the total number of candidate keys considered by the owning fetcher.
   */
  @Override
  public long countAllKeys(ClientContext context) {
    return callbacks.fetcher().countKeys();
  }

  /**
   * Counts the number of keys that are currently sendable by this request.
   *
   * <p>The request scheduler can use this count to determine whether any work remains to be sent.
   * This store-check getter never produces sendable keys because it does not perform network
   * fetching. It therefore always reports {@code 0}, consistent with {@link
   * #chooseKey(KeysFetchingLocally, ClientContext)} returning {@code null}.
   *
   * @param context client context used for accounting; must not be null.
   * @return {@code 0}, because no keys from this getter are sent to the network.
   */
  @Override
  public long countSendableKeys(ClientContext context) {
    return 0;
  }

  /**
   * Returns the {@link RequestClient} to use for accounting and scheduling.
   *
   * <p>Although this getter does not perform network I/O, it still participates in the same
   * scheduling and accounting paths as other requests. Selecting the client based on the real-time
   * flag of the owning requester keeps the probe aligned with the rest of the USK polling workflow
   * and ensures it is attributed to the correct request queue.
   *
   * @return the request client matching the owner's real-time scheduling mode.
   */
  @Override
  public RequestClient getClient() {
    return owner.realTimeFlag() ? USKManager.rcRT : USKManager.rcBulk;
  }

  /**
   * Returns the {@link ClientRequester} that owns this request.
   *
   * <p>The request machinery uses this link to attribute accounting and cancellation. This getter
   * is a helper object and does not represent an independent client request, so it returns the
   * owner requester supplied at construction time. Callers should treat the returned requester as
   * the authoritative owner of this probe and its scheduling.
   *
   * @return the owner requester that owns this store-check probe.
   */
  @Override
  public ClientRequester getClientRequest() {
    return owner;
  }

  /**
   * Returns the priority class for this request.
   *
   * <p>The priority is delegated to the owning {@link USKFetcher} so that the store-check probe is
   * scheduled with the same urgency as the rest of the USK polling activity. This avoids the probe
   * establishing its own priority policy and keeps scheduling decisions centralized in the fetcher.
   *
   * @return the priority class value provided by the owning fetcher.
   */
  @Override
  public short getPriorityClass() {
    return callbacks.fetcher().getPriorityClass();
  }

  /**
   * Reports whether this request should be treated as canceled.
   *
   * <p>The request is considered canceled once {@link #preRegister(ClientContext, boolean)} has
   * completed (the {@code done} flag is set in a {@code finally} block), or when the owning {@link
   * USKFetcher} has been canceled. This makes the probe single-shot and prevents it from being
   * rescheduled indefinitely.
   *
   * @return {@code true} if this probe is done or the owning fetcher is canceled.
   */
  @Override
  public boolean isCancelled() {
    return done || callbacks.isCancelled();
  }

  /**
   * Indicates whether this request is based on SSK keys.
   *
   * <p>USK datastore lookups are performed using SSK-derived keys, so this getter always reports
   * {@code true} to match the underlying key type expectations of the request machinery. This
   * classification can influence request routing, accounting, and key-handling behavior. It has no
   * side effects and does not vary, per instance.
   *
   * @return {@code true}, as this getter operates on SSK-derived keys.
   */
  @Override
  public boolean isSSK() {
    return true;
  }

  /**
   * Returns the next wakeup time for this request.
   *
   * <p>This getter is used for a local store-check pass and does not manage its own timed wakeup.
   * Any retrying or periodic behavior is controlled by the owning {@link USKFetcher}, so this
   * method returns a constant value. The parameters are accepted to satisfy the {@link SendableGet}
   * contract but are not used by this implementation.
   *
   * @param context client context associated with the request; must not be null.
   * @param now current time supplied by the scheduler; ignored by this implementation.
   * @return {@code 0}, as this getter does not schedule a dedicated wakeup time.
   */
  @Override
  public long getWakeupTime(ClientContext context, long now) {
    return 0;
  }

  /**
   * Returns the {@link ClientGetState} associated with this request.
   *
   * <p>The request machinery uses the returned state for bookkeeping and cancellation. The
   * store-check getter is an implementation detail of {@link USKFetcher} and therefore reports the
   * fetcher as the owner of the client-get state rather than introducing a separate state object.
   * This keeps state transitions centralized and consistent with the rest of the USK polling flow.
   *
   * @return the owning {@link USKFetcher} instance, used as the client-get state.
   */
  @Override
  protected ClientGetState getClientGetState() {
    return callbacks.fetcher();
  }
}
