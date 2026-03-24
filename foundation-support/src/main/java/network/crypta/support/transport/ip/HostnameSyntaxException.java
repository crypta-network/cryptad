package network.crypta.support.transport.ip;

import java.io.Serial;

/**
 * Signals that a host name (or, when permitted, an IP literal) does not conform to the expected
 * syntax.
 *
 * <p>This checked exception is raised by hostname/IP parsers and validators when the supplied input
 * fails basic syntactic checks. It does not imply that a DNS lookup was attempted or that a host is
 * unreachable; it strictly represents a formatting problem with the value.
 *
 * <p>Typical sources include:
 *
 * <ul>
 *   <li>Constructors and readers that validate input (e.g., {@link
 *       network.crypta.io.comm.FreenetInetAddress#FreenetInetAddress(java.io.DataInput, boolean)}
 *       when {@code checkHostnameOrIPSyntax} is {@code true}).
 *   <li>Utilities that check host/IP syntax prior to storage or publication (see {@link
 *       HostnameUtil#isValidHostname(String, boolean)}).
 * </ul>
 *
 * <p>Instances are immutable and thread-safe.
 *
 * <p>Usage guidelines:
 *
 * <ul>
 *   <li>Catching this exception is appropriate when rejecting user input before performing network
 *       I/O.
 *   <li>To distinguish syntax errors from resolution failures, also consider {@link
 *       java.net.UnknownHostException} for DNS lookup results.
 * </ul>
 */
public class HostnameSyntaxException extends Exception {
  @Serial private static final long serialVersionUID = -1;
}
