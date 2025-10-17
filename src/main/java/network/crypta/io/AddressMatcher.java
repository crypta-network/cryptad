package network.crypta.io;

import java.net.InetAddress;

/**
 * Strategy interface for testing whether an IP address matches a rule.
 *
 * <p>This interface abstracts the notion of an "address predicate" so callers can evaluate whether
 * a given {@link InetAddress} should be included, excluded, or otherwise recognized by some
 * higher-level component (e.g., ACLs, bind/allow lists, or diagnostics). The matching semantics are
 * implementation-defined: an implementation may represent a single address, a subnet (CIDR), a
 * range, a hostname pattern, or a composite of multiple rules.
 *
 * <p>Thread-safety: unless stated otherwise by a concrete implementation, instances should be
 * considered thread-safe for concurrent reads (calls to {@link #matches(InetAddress)} and {@link
 * #getHumanRepresentation()}). Implementations that maintain mutable state MUST document any
 * concurrency constraints.
 *
 * <p>Nullability: parameters are assumed to be non-null unless explicitly documented by an
 * implementation. Passing {@code null} may result in a {@link NullPointerException} or other
 * implementation-specific behavior.
 *
 * <p>Performance: typical implementations complete in constant time relative to the size of the
 * rule (for example, bitwise checks for CIDR), but this is not guaranteed and depends on the
 * concrete matcher.
 *
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id$
 */
public interface AddressMatcher {
  /**
   * Tests whether the provided address satisfies this matcher's rule.
   *
   * <p>Implementations define what it means for an address to "match" (exact equality, subnet
   * containment, pattern resolution, etc.). The method performs no I/O and must not block on
   * network lookups; any hostname-to-address resolution should occur at construction time or be
   * clearly documented if deferred.
   *
   * @param address the IP address to test.
   * @return {@code true} if the address matches according to this rule; {@code false} otherwise.
   * @throws RuntimeException implementations may throw unchecked exceptions for invalid internal
   *     state or unsupported address families; no checked exceptions are declared.
   */
  boolean matches(InetAddress address);

  /**
   * Returns a human-readable representation of the rule encoded by this matcher.
   *
   * <p>The returned string is suitable for logs, diagnostics, or UI. Its exact format is
   * implementation-defined (for example, a literal address, a CIDR such as {@code 10.0.0.0/8}, a
   * range, or a descriptive phrase). Callers must not rely on it being parseable or stable for
   * long-term persistence unless the specific implementation documents such guarantees.
   *
   * @return a human-friendly description of the matching rule; never {@code null}.
   */
  String getHumanRepresentation();
}
