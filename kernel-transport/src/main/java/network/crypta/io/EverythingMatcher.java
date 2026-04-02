package network.crypta.io;

import java.net.InetAddress;

/**
 * An {@link AddressMatcher} that matches every address.
 *
 * <p>This implementation represents the trivial "allow all" rule: {@link #matches(InetAddress)}
 * always returns {@code true} regardless of the provided address, and {@link
 * #getHumanRepresentation()} returns a single asterisk ({@code "*"}) as a conventional wildcard
 * indicator.
 *
 * <p>Intended use cases include default-allow configurations, testing, and sentinel values where a
 * matcher is required but no restriction is desired.
 *
 * <p>Thread-safety: instances are stateless and therefore thread-safe.
 *
 * <p>Performance: calls complete in constant time (O(1)).
 */
public class EverythingMatcher implements AddressMatcher {
  /**
   * Returns {@code true} for any input.
   *
   * <p>The parameter value is not inspected by this implementation. It performs no I/O and never
   * blocks.
   *
   * @param address the address to test; the value is ignored.
   * @return always {@code true}.
   * @throws RuntimeException never thrown by this implementation.
   */
  @Override
  public boolean matches(InetAddress address) {
    return true;
  }

  /**
   * Returns the wildcard string {@code "*"}.
   *
   * <p>The asterisk is a conventional representation of a rule that matches everything.
   *
   * @return {@code "*"} to denote an unrestricted match.
   */
  @Override
  public String getHumanRepresentation() {
    return "*";
  }
}
