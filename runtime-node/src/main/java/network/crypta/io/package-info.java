/**
 * Networking utilities for working with IP addresses and inbound server endpoints.
 *
 * <p>This package provides building blocks used by higher-level components to listen for and accept
 * incoming connections and to decide which clients may connect. Core areas include:
 *
 * <ul>
 *   <li><b>Address allow/deny checks</b> — a small, literal-only matching DSL parsed by {@link
 *       network.crypta.io.AllowedHosts}. It supports IPv4/IPv6 literals, dotted or CIDR masks (for
 *       example, {@code 192.168.1.0/24} or {@code 2001:db8::/64}), and a wildcard token ({@code
 *       *}). Hostnames are not resolved.
 *   <li><b>Address matchers</b> — family-specific implementations such as {@link
 *       network.crypta.io.Inet4AddressMatcher}, {@link network.crypta.io.Inet6AddressMatcher}, and
 *       {@link network.crypta.io.EverythingMatcher} that evaluate a client {@link
 *       java.net.InetAddress} against the configured rules.
 *   <li><b>Server endpoint abstraction</b> — {@link network.crypta.io.NetworkInterface} wraps one
 *       or more {@link java.net.ServerSocket} instances to bind on multiple addresses, filter
 *       connections using {@link network.crypta.io.AllowedHosts}, and expose a single {@code
 *       accept()} queue.
 *   <li><b>Auxiliary helpers</b> — utilities for tracking/identifying addresses and writing to
 *       streams (for example, {@link network.crypta.io.AddressIdentifier}, {@link
 *       network.crypta.io.AddressTracker}, and {@link
 *       network.crypta.io.WritableToDataOutputStream}).
 * </ul>
 *
 * <p>Defaults and behavior:
 *
 * <ul>
 *   <li>When no explicit bind or allowlist is provided, the code defaults to loopback-only binding
 *       as indicated by {@link network.crypta.io.NetworkInterface#DEFAULT_BIND_TO}.
 *   <li>Tokens in allowlists must be numeric address literals; DNS names are ignored.
 *   <li>Concurrency characteristics are documented on each type. The implementation favors explicit
 *       locking for Accept queues and atomic replacement for rule updates.
 * </ul>
 *
 * <p>Related packages:
 *
 * <ul>
 *   <li>{@link network.crypta.io.comm} — peer communication, socket handlers, and message framing.
 *   <li>{@link network.crypta.io.xfer} — block/bulk transfer primitives and throttling.
 * </ul>
 */
package network.crypta.io;
