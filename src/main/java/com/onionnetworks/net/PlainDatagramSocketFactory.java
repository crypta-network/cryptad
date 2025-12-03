// (c) Copyright 2000 Justin F. Chapweske
// (c) Copyright 2000 Ry4an C. Brase

package com.onionnetworks.net;

import java.io.*;
import java.net.*;

/**
 * Simple factory that produces unadorned {@link DatagramSocket} instances for UDP communication.
 *
 * <p>This implementation exists as the baseline socket provider for components that accept a
 * configurable factory. It performs no decoration or state caching; every call returns a newly
 * constructed socket created directly through the standard JDK APIs. Use it when you want the
 * operating system and JVM to choose all default parameters such as buffer sizes, socket options,
 * and address reuse policies. The factory is stateless and thread-safe, making it suitable for
 * shared reuse across subsystems that simply need a means of producing sockets on demand.
 *
 * <p>Because sockets created by this factory are mutable, callers should immediately configure any
 * desired options (timeouts, broadcast flags, traffic class settings) before exposing the socket to
 * other threads. Responsibility for closing the socket remains entirely with the caller to avoid
 * exhausting native file descriptors or port allocations. There is no retry logic, pooling, or
 * monitoring embedded here; higher-level components should layer those behaviors as needed while
 * leaving this class as a predictable, low-overhead creation utility.
 *
 * <ul>
 *   <li>Provides the most direct access to {@code DatagramSocket} construction.
 *   <li>Imposes no custom defaults, filters, or lifecycle hooks.
 *   <li>Safe to call concurrently; each invocation yields an independent socket.
 * </ul>
 */
public class PlainDatagramSocketFactory extends DatagramSocketFactory {

  /** Constructs a new instance of this factory with no retained state. */
  public PlainDatagramSocketFactory() {
    // Intentionally empty: factory holds no configuration and relies on JDK defaults.
  }

  /**
   * Creates plain {@link DatagramSocket} instances with no additional configuration or wrapping.
   *
   * <p>This factory is the simplest implementation used by callers that want a vanilla UDP socket
   * without transport filters, monitoring hooks, or custom socket options. It delegates entirely to
   * the JDK constructors, so address binding, buffer sizes, and platform defaults are chosen by the
   * underlying Java networking stack and operating system. Typical call patterns include
   * provisioning a lightweight socket for stateless message exchange or supplying the factory to
   * components that expect a pluggable socket creator. The factory itself is stateless and may be
   * reused safely across threads.
   *
   * <p>Because the produced sockets are mutable and not pooled, each invocation returns a newly
   * allocated socket with its own lifecycle. Callers are responsible for applying any desired
   * socket options (for example, timeouts) immediately after creation and for closing the socket
   * when no longer needed to avoid file descriptor leaks. No concurrency control is performed
   * within the factory; thread safety concerns are limited to the caller's own use of the resulting
   * {@code DatagramSocket} instances.
   *
   * <ul>
   *   <li>Returns unwrapped UDP sockets using standard JDK behavior.
   *   <li>Stateless and thread-safe to invoke concurrently.
   *   <li>Does not alter buffer sizes, timeouts, or platform defaults.
   * </ul>
   *
   * @see DatagramSocketFactory
   * @see DatagramSocket
   */
  public DatagramSocket createDatagramSocket() throws IOException {
    return new DatagramSocket();
  }

  /**
   * Creates a {@link DatagramSocket} bound to a specific local port using platform defaults.
   *
   * <p>This method is appropriate when a deterministic port is required for inbound traffic or for
   * interoperability with peers that expect a stable source port. The socket is created in a bound
   * but otherwise unconfigured state; callers should promptly set options such as receive buffers
   * or timeouts if they deviate from defaults. The operation is not idempotent: repeated calls will
   * attempt to bind separate sockets to the same port and will fail when the port is already in use
   * or reserved by the operating system. The returned socket must be closed by the caller.
   *
   * @param port local UDP port number to bind; use {@code 0} to request an ephemeral port when a
   *     fixed port is unavailable.
   * @return newly created bound socket that the caller owns and should close after use.
   * @throws IOException if binding fails due to permission constraints, port conflicts, or resource
   *     exhaustion in the underlying network stack.
   */
  public DatagramSocket createDatagramSocket(int port) throws IOException {
    return new DatagramSocket(port);
  }

  /**
   * Creates a {@link DatagramSocket} bound to a specific port and local address.
   *
   * <p>Use this variant when an application must bind to a particular network interface or IP
   * address, such as when operating on a multihomed host or constraining traffic to a private
   * subnet. The method performs no validation beyond delegating to the JDK constructor; the caller
   * should ensure that the address represents a local interface and that the port is appropriate
   * for the intended protocol flow. As with the other factory methods, each invocation allocates a
   * new socket instance that remains mutable and must be closed by the caller once communication is
   * complete.
   *
   * @param port local UDP port number to bind; must be within the valid user-port range supported
   *     by the host operating system.
   * @param iaddr local {@link InetAddress} representing the interface to bind; must not be {@code
   *     null} and should correspond to an address assigned to the current host.
   * @return newly allocated datagram socket bound to the requested address and port for caller
   *     managed communication.
   * @throws IOException if the requested address or port cannot be bound because of permissions,
   *     conflicts, or resource limits enforced by the platform.
   */
  public DatagramSocket createDatagramSocket(int port, InetAddress iaddr) throws IOException {

    return new DatagramSocket(port, iaddr);
  }
}
