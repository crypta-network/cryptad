package network.crypta.client.async;

import network.crypta.keys.Key;

/**
 * Strategy interface for deriving a salted, scheduler-scoped byte array from a {@link Key}.
 *
 * <p>This abstraction decouples components that need a stable identifier for request tracking from
 * the details of how that identifier is derived. Implementations typically combine properties of
 * the input key with an internal salt to produce an opaque byte sequence suitable for use as a map
 * key or set membership token. Equality of the returned arrays is meaningful only within the scope
 * of a single {@code KeySalter} instance: the same key salted by the same instance produces the
 * same bytes, while different instances (or different lifetimes) may intentionally yield different
 * results to avoid unwanted cross-run correlations.
 *
 * <p>The salted representation is not a serialization of the key and must be treated as
 * implementation-defined and non-reversible. Callers should not assume a specific length or
 * structure beyond general byte-array semantics. Implementations are expected to be thread-safe for
 * concurrent calls and side-effect free; the method returns a fresh array for each invocation and
 * does not retain references provided by callers.
 *
 * <ul>
 *   <li>Stable within an instance: identical inputs map to identical outputs.
 *   <li>Opaque to callers: the content and length are not part of the API.
 *   <li>Scope-bound: outputs from different salters must not be compared for equality.
 * </ul>
 *
 * @see ClientRequestScheduler#saltKey(boolean, Key)
 * @see ClientRequestScheduler#getGlobalKeySalter(boolean)
 * @see KeyListenerTracker
 * @author toad
 */
public interface KeySalter {

  /**
   * Returns a salted, opaque representation of the supplied {@link Key} for internal tracking.
   *
   * <p>The derivation is deterministic within the lifetime and configuration of this {@code
   * KeySalter} instance and is intended for use as a lookup key in in-memory data structures. The
   * returned array is newly allocated and should be treated as immutable by callers. The exact
   * bytes, length, and any hashing/salting algorithm are implementation details and may vary
   * between environments or across restarts.
   *
   * <pre>{@code
   * // Example: obtain a salted identifier for a key
   * KeySalter salter = scheduler.getGlobalKeySalter(false);
   * byte[] trackingId = salter.saltKey(key);
   * }</pre>
   *
   * @param key the key whose scheduler-scoped salted identifier should be derived; must not be
   *     {@code null}; accepted concrete key types determine which key properties are used
   * @return a newly allocated, opaque byte array; equal keys salted by the same instance produce
   *     equal arrays; content is not stable across different salters or executions
   * @throws NullPointerException if {@code key} is {@code null}
   */
  byte[] saltKey(Key key);
}
