package network.crypta.io.comm;

/**
 * Base class for all transports. We have a single object of this type for both incoming and
 * outgoing packets, but multiple instances for different instances of the transport e.g. on
 * different ports, with different crypto backends etc.
 *
 * @author toad
 */
public interface SocketHandler {}
