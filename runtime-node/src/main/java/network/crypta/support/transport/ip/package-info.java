/**
 * Utilities and helpers for parsing, validating, and classifying host and IP address strings.
 *
 * <p>The types in this package provide small, side-effect-free checks that are used throughout the
 * transport layer to decide whether an address is suitable for publication (e.g., in a node
 * reference) and for general sanity checking of input. The code is intentionally conservative and
 * focuses on frequently encountered address forms rather than providing a full DNS/IDNA stack.
 *
 * <p>Key components
 *
 * <ul>
 *   <li>{@link network.crypta.support.transport.ip.IPUtil} — IP address classification helpers
 *       (IPv4/IPv6). Notably:
 *       <ul>
 *         <li>{@code isSiteLocalAddress(...)} recognizes IPv6 Unique Local Addresses ({@code
 *             fc00::/7}) and the deprecated site-local range ({@code fec0::/10}), and otherwise
 *             delegates to the JDK for non-IPv6 addresses.
 *         <li>{@code isValidAddress(...)} rejects wildcard and multicast addresses, and optionally
 *             rejects local-only addresses (loopback, link-local, site/unique-local). For IPv4, it
 *             also rejects {@code 0.0.0.0/8}.
 *       </ul>
 *   <li>{@link network.crypta.support.transport.ip.HostnameUtil} — Lightweight validation of
 *       hostnames with an option to accept numeric IP literals. Hostname checks are ASCII-only and
 *       intended to accept ACE/IDNA (Punycode) labels; they require at least one dot and a 2–6
 *       letter TLD by design.
 *   <li>{@link network.crypta.support.transport.ip.HostnameSyntaxException} — Checked exception
 *       thrown by components that perform strict syntax validation when the given value is not a
 *       valid hostname or IP literal.
 * </ul>
 *
 * <p>Threading and side effects
 *
 * <ul>
 *   <li>All utilities are stateless and thread-safe. Methods do not perform I/O and do not mutate
 *       shared state.
 * </ul>
 *
 * <p>Common failure modes
 *
 * <ul>
 *   <li>Syntax errors are reported via {@link
 *       network.crypta.support.transport.ip.HostnameSyntaxException} by callers that opt into
 *       strict checking (see usages in {@code network.crypta.io.comm.FreenetInetAddress}).
 *   <li>Resolution failures should be surfaced as {@link java.net.UnknownHostException} by code
 *       that performs DNS lookups; this package intentionally does not do network I/O.
 * </ul>
 *
 * <p>Limitations
 *
 * <ul>
 *   <li>Hostname validation is not a full IDNA implementation. Unicode hostnames must be provided
 *       in ACE (Punycode) form.
 *   <li>Bracketed IPv6 literals such as {@code [::1]} are not recognized by the hostname validator;
 *       supply raw address literals.
 *   <li>Top-level domains longer than six ASCII letters are rejected by {@code HostnameUtil}.
 *   <li>IPv6-mapped IPv4 addresses are not specially classified; callers should normalize them to
 *       IPv4 if they require IPv4-specific handling.
 * </ul>
 */
package network.crypta.support.transport.ip;
