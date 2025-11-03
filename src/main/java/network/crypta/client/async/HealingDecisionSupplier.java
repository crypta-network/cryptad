package network.crypta.client.async;

import java.util.function.Supplier;
import network.crypta.node.Location;
import network.crypta.node.NodeStarter;

/**
 * Supplies decisions that determine whether the node should perform a healing insert for a given
 * key location.
 *
 * <p>This helper focuses healing on the fraction of the keyspace from which the node would most
 * plausibly receive traffic if it were one of the long-distance peers of a real inserter. In
 * opennet deployments, blindly healing every key can be indistinguishable from user inserts to an
 * adversarial neighbor and therefore leaks behavior. By specializing healing so that it resembles
 * normal request forwarding, we reduce this risk while still contributing meaningfully to network
 * health.
 *
 * <p>The decision policy is distance-aware. Keys closer to the node's own location are healed with
 * higher probability using a continuous function of distance; far-away keys are healed at a low
 * fixed rate. This mirrors typical routing patterns, reduces the number of hops taken by healing
 * inserts, and helps limit unnecessary load.
 *
 * <p>Thread-safety: Instances are immutable after construction provided the suppliers given at
 * creation are themselves thread-safe and side effect free. Callers may reuse a single instance
 * across threads as long as the underlying suppliers tolerate concurrent access.
 */
public class HealingDecisionSupplier {
  private final Supplier<Double> currentNodeLocation;
  private final Supplier<Boolean> isOpennetEnabled;
  private final Supplier<Double> randomNumberSupplier;

  /**
   * Creates a supplier that decides whether to heal a block based on the current node location,
   * opennet enablement, and a cryptographically strong random source.
   *
   * <p>The {@code currentNodeLocation} and {@code isOpennetEnabled} suppliers are invoked for each
   * decision. The random source is derived from the globally shared secure RNG used by the node
   * runtime so that probabilities are stable and unbiased.
   *
   * @param currentNodeLocation provides the node's keyspace location in {@code [0.0, 1.0)}; values
   *     outside this range are treated as implementation-defined and should be avoided.
   * @param isOpennetEnabled indicates whether opennet mode is active; when {@code false}, healing
   *     is considered safe and decisions default to permitting healing.
   */
  public HealingDecisionSupplier(
      Supplier<Double> currentNodeLocation, Supplier<Boolean> isOpennetEnabled) {

    this.currentNodeLocation = currentNodeLocation;
    this.isOpennetEnabled = isOpennetEnabled;
    randomNumberSupplier = NodeStarter.getGlobalSecureRandom()::nextDouble;
  }

  HealingDecisionSupplier(
      Supplier<Double> currentNodeLocation,
      Supplier<Boolean> isOpennetEnabled,
      Supplier<Double> randomNumberSupplier) {

    this.currentNodeLocation = currentNodeLocation;
    this.isOpennetEnabled = isOpennetEnabled;
    this.randomNumberSupplier = randomNumberSupplier;
  }

  /**
   * Decides whether to heal for the provided key location.
   *
   * <p>When opennet is disabled the decision allows healing unconditionally, reflecting the lower
   * exposure to Sybil-style observation on darknet. When opennet is enabled, the decision applies a
   * distance-sensitive probability so that healing resembles ordinary routing: nearby keys are more
   * likely to be healed, and far-away keys are allowed with a low fixed chance. The
   * distance-sensitive curve is continuous and monotonic with respect to proximity.
   *
   * @param keyLocation the key's location in the ring, expressed in {@code [0.0, 1.0)} where values
   *     wrap modulo {@code 1.0}; inputs outside the range are not validated and may yield
   *     implementation-defined behavior.
   * @return {@code true} when healing should proceed for this key and {@code false} otherwise; the
   *     result reflects current opennet status and a random draw, and it is not cached across
   *     invocations.
   * @throws NullPointerException if the opennet-enabled supplier yields {@code null}. Callers must
   *     ensure the supplier consistently returns a non-null Boolean value.
   */
  public boolean shouldHeal(double keyLocation) {
    Boolean opennet = isOpennetEnabled.get();
    if (opennet == null) {
      throw new NullPointerException("isOpennetEnabled returned null");
    }
    if (!opennet) {
      // darknet is safer against sybil attack, so we can heal fully
      return true;
    }
    double randomBetweenZeroAndOne = randomNumberSupplier.get();
    return shouldHealBlock(currentNodeLocation.get(), keyLocation, randomBetweenZeroAndOne);
  }

  /**
   * Specialize healing: we want healing traffic to look like regular forwarding.
   *
   * <p>Far away blocks would be unlikely to reach our node as request, so we reduce healing there:
   * only accept 10% of those.
   *
   * <p>When a key is close to our location, we use a continuous function depending on the distance
   * to choose a probability. The closer to our node, the higher the probability of healing. As a
   * side effect this reduces the hops healing inserts take, reducing the overall load on the
   * network.
   *
   * <p>The continuous function is gauged to accept 50% of the keys close to our node: a peak at our
   * own location for which the area below the curve between 0 and 0.1 sums up to 0.5.
   *
   * <p>Close keys are those in our 20% of the keyspace: the ones that would reach us if we were one
   * of 5 long distance peers of a peer node. These are the keys for which we are most likely to be
   * the best next hop when seen from the originator.
   */
  private static boolean shouldHealBlock(
      double nodeLocation, double keyLocation, double randomBetweenZeroAndOne) {
    double distanceToNodeLocation = Location.distance(nodeLocation, keyLocation);
    // If the key is inside "our" 20% of the keyspace, heal it with 50% probability.
    if (distanceToNodeLocation < 0.1) {
      // accept 50%, specialized to our own location (0.5 ** 4 ~ 0.0625). Accept 70% which are going
      // to our short distance peers (0.32 ** 4 ~ 0.01), 78% of those which could be reached via a
      // direct short distance FOAF (distance 0.02).
      double randomToPower4 = Math.pow(randomBetweenZeroAndOne, 4);
      return distanceToNodeLocation < randomToPower4;
    } else {
      // if the key is a long distance key for us, heal it with 10% probability: it is unlikely that
      // this would have reached us. Setting this to 0 could amplify a keyspace takeover attack.
      return randomBetweenZeroAndOne > 0.9;
    }
  }
}
