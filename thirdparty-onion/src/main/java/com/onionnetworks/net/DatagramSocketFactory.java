// (c) Copyright 2000 Justin F. Chapweske
// (c) Copyright 2000 Ry4an C. Brase

package com.onionnetworks.net;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * Factory for creating {@link java.net.DatagramSocket} instances with consistent configuration
 * across calling code.
 *
 * <p>Implementations centralize UDP socket creation so callers do not hard-code constructor choices
 * or platform checks. A single factory instance can be shared by components that need to open
 * sockets for listening, request-response exchanges, or background heartbeats while keeping the
 * selection of socket options in one place. Typical usage is to obtain the default implementation
 * via {@link #getDefault()} and delegate all socket allocation to it.
 *
 * <p>Factories are usually lightweight and either stateless or thread-safe so they can be reused by
 * multiple networking subsystems. Implementations decide how sockets are bound (wildcard versus
 * specific interface), whether they remain unconnected, and whether platform-specific tuning such
 * as buffer sizing or traffic class hints is applied. Callers should treat returned sockets as
 * owned by the caller and close them when no longer needed to release file descriptors.
 *
 * <ul>
 *   <li>Provides a single point to customize binding addresses and ports.
 *   <li>Hides platform differences behind a narrow creation interface.
 *   <li>Supports test doubles for deterministic UDP behavior in unit tests.
 * </ul>
 *
 * <pre>{@code
 * DatagramSocketFactory factory = DatagramSocketFactory.getDefault();
 * DatagramSocket socket = factory.createDatagramSocket();
 * // Use socket for sends/receives, then close when finished.
 * }</pre>
 *
 * @see PlainDatagramSocketFactory
 */
public abstract class DatagramSocketFactory {

  /**
   * Protected base constructor for subclassing factories.
   *
   * <p>Subclasses are expected to be lightweight and reusable; they typically store configuration
   * such as preferred bind addresses or socket options and expose them via the creation methods.
   * Extending classes should avoid expensive state initialization here because factories may be
   * instantiated eagerly during application bootstrapping or testing, and they are generally shared
   * across threads. No socket resources are allocated by this constructor; resource acquisition is
   * deferred to the individual {@code createDatagramSocket} methods.
   */
  protected DatagramSocketFactory() {}

  /**
   * Creates a new datagram socket using the factory's default binding strategy.
   *
   * <p>Implementations may bind to an ephemeral port on the wildcard address or apply custom
   * defaults; callers should not assume connectivity or binding to a particular interface. The
   * returned socket is ready for send and receive operations and may be further configured by the
   * caller (for example, setting timeouts or buffer sizes) before use. Each invocation must produce
   * a fresh socket; the caller owns the lifecycle and must close it to release the underlying file
   * descriptor. The operation is not idempotent because a new socket is allocated every time it is
   * invoked.
   *
   * @return a new {@link DatagramSocket} configured according to this factory's defaults and owned
   *     by the caller
   * @throws IOException if the socket cannot be created or bound by the implementation
   */
  @SuppressWarnings("unused")
  public abstract DatagramSocket createDatagramSocket() throws IOException;

  /**
   * Creates a datagram socket bound to a specific local port.
   *
   * <p>The factory decides the local address and other options, while the caller specifies the
   * requested UDP port. Passing {@code 0} delegates port selection to the operating system, which
   * is useful for temporary sockets. Implementations must either bind the returned socket to the
   * given port or fail with an exception; they should not silently choose a different port. Callers
   * are responsible for validating that the selected port is available for their use case and for
   * closing the socket when finished to free system resources.
   *
   * @param port local UDP port to bind; use {@code 0} to request an ephemeral port
   * @return a new {@link DatagramSocket} bound to the requested port and owned by the caller
   * @throws IOException if the socket cannot be created or the port cannot be bound
   */
  @SuppressWarnings("unused")
  public abstract DatagramSocket createDatagramSocket(int port) throws IOException;

  /**
   * Creates a datagram socket bound to a specific local address and port.
   *
   * <p>This variant allows callers to select both the bind address (network interface) and port,
   * which is useful when multiple interfaces are present or when binding must be restricted to a
   * particular address family. The port behaves like {@link #createDatagramSocket(int)}; specifying
   * {@code 0} requests an ephemeral port from the operating system. Implementations must honor the
   * provided address and port or throw an exception rather than falling back to defaults. The
   * caller owns the returned socket and must close it when no longer needed. This method is not
   * idempotent because each call allocates a new socket instance.
   *
   * @param port local UDP port to bind; use {@code 0} when any available port is acceptable
   * @param iaddr local {@link InetAddress} to bind; must not be {@code null} for deterministic
   *     binding
   * @return a {@link DatagramSocket} bound to the specified address and port for caller ownership
   * @throws IOException if the socket cannot be created or bound to the requested address/port
   */
  @SuppressWarnings("unused")
  public abstract DatagramSocket createDatagramSocket(int port, InetAddress iaddr)
      throws IOException;

  /**
   * Returns the default factory that creates platform-standard datagram sockets.
   *
   * <p>The default implementation, {@link PlainDatagramSocketFactory}, delegates to the JDK's
   * built-in {@link DatagramSocket} constructors without adding custom options. It is suitable for
   * most callers that simply need UDP sockets configured with system defaults. The returned factory
   * is lightweight and may be reused across threads; callers may also instantiate it repeatedly
   * with minimal cost because it holds no external resources. Consider supplying a custom factory
   * when sockets must be preconfigured with specific buffer sizes, traffic class values, or binding
   * constraints.
   *
   * @return a new {@link PlainDatagramSocketFactory} that follows JDK default socket semantics
   */
  public static DatagramSocketFactory getDefault() {
    return new PlainDatagramSocketFactory();
  }
}
