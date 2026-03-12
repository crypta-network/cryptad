package network.crypta.client.async;

import java.util.List;
import network.crypta.keys.ClientSSKBlock;

/**
 * Builds plan objects for handling successful or discovered USK editions.
 *
 * <p>This helper centralizes the decision-making data needed when a polling attempt succeeds or
 * discovers a newer edition. Callers use it to construct immutable-looking plan objects that carry
 * flags about whether to decode data, which attempts should be canceled, and whether a store check
 * should be registered immediately. The planner does not execute any actions itself; it simply
 * prepares structured data for the owning {@link USKFetcher} or related coordinators.
 *
 * <p>The class is stateless and thread-safe, and it may be reused freely across scheduling cycles.
 * Plan instances are mutable data holders and are typically short-lived, created for a single
 * scheduling decision, and then discarded.
 *
 * <ul>
 *   <li>Creates plan objects for successful fetches or found editions.
 *   <li>Encodes decode and registration decisions in a small data structure.
 *   <li>Provides a reusable helper for decode-eligibility checks.
 * </ul>
 */
final class USKSuccessPlanner {
  /** Creates a stateless planner instance. */
  USKSuccessPlanner() {}

  /**
   * Plan describing how to handle a successful fetch.
   *
   * <p>The plan records whether to decode data, the current latest edition value, and whether
   * registration should happen immediately. It also includes any polling attempts that should be
   * terminated after successful handling is completed.
   */
  static final class SuccessPlan {
    /** Whether the caller should decode the associated data block. */
    boolean decode;

    /** Current latest edition value after applying the successful result. */
    long curLatest;

    /** Whether the caller should register follow-up work immediately. */
    boolean registerNow;

    /** Attempts that should be canceled after the success is processed. */
    List<USKAttempt> killAttempts;

    /** Creates an empty success plan with default values. */
    SuccessPlan() {}
  }

  /**
   * Plan describing how to handle a discovered edition without a full success path.
   *
   * <p>The plan records whether to decode data, whether a store check should be registered
   * immediately, and which polling attempts should be terminated after handling the discovery.
   */
  static final class FoundPlan {
    /** Whether the caller should decode the associated data block. */
    boolean decode;

    /** Attempts that should be canceled after the discovery is processed. */
    List<USKAttempt> killAttempts;

    /** Whether the caller should register follow-up work immediately. */
    boolean registerNow;

    /** Creates an empty found plan with default values. */
    FoundPlan() {}
  }

  /**
   * Creates a plan for handling a successful fetch.
   *
   * <p>The returned plan aggregates the caller's decision flags and the list of attempts that
   * should be terminated after success handling. The method does not validate the inputs; it simply
   * packages them for downstream consumers.
   *
   * @param decode whether the success path should decode the returned data block
   * @param curLatest latest edition value after applying the successful fetch
   * @param registerNow whether follow-up registration should occur immediately
   * @param killAttempts polling attempts to cancel after success handling; may be empty but not
   *     null
   * @return a success plan populated with the provided values
   */
  SuccessPlan createSuccessPlan(
      boolean decode, long curLatest, boolean registerNow, List<USKAttempt> killAttempts) {
    SuccessPlan plan = new SuccessPlan();
    plan.decode = decode;
    plan.curLatest = curLatest;
    plan.registerNow = registerNow;
    plan.killAttempts = killAttempts;
    return plan;
  }

  /**
   * Creates a plan for handling a newly discovered edition.
   *
   * <p>The returned plan captures decode and registration choices along with any polling attempts
   * that should be terminated after the discovery is processed.
   *
   * @param decode whether the discovery path should decode the returned data block
   * @param registerNow whether follow-up registration should occur immediately
   * @param killAttempts polling attempts to cancel after handling the discovery; may be empty but
   *     not null
   * @return a found plan populated with the provided values
   */
  FoundPlan createFoundPlan(boolean decode, boolean registerNow, List<USKAttempt> killAttempts) {
    FoundPlan plan = new FoundPlan();
    plan.decode = decode;
    plan.registerNow = registerNow;
    plan.killAttempts = killAttempts;
    return plan;
  }

  /**
   * Determines whether the given result should be decoded.
   *
   * <p>The decision is based on the current latest edition value, the last known edition, and
   * whether the caller has requested a no-update path without a data block. A {@code null} block is
   * treated as non-decodable when {@code dontUpdate} is set.
   *
   * @param curLatest current latest edition value tracked by the caller
   * @param lastEd last known edition value to compare against
   * @param dontUpdate whether the caller is explicitly avoiding updates
   * @param block decoded block candidate; may be null when only metadata is available
   * @return {@code true} when the result is eligible for decoding
   */
  static boolean shouldDecode(
      long curLatest, long lastEd, boolean dontUpdate, ClientSSKBlock block) {
    return curLatest >= lastEd && !(dontUpdate && block == null);
  }
}
