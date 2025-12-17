package network.crypta.pluginmanager;

import java.net.InetAddress;

/**
 * Detected public IP address and NAT reachability information.
 *
 * <p>This is a small data container returned by implementations of {@code FredPluginIPDetector}
 * after probing the host's externally visible IP address and UDP reachability characteristics.
 * Callers typically treat it as a snapshot of the best information available at the time of
 * detection and use it to decide how aggressively to attempt inbound connections, hole punching, or
 * fallback strategies.
 *
 * <p>The {@link #natType} field stores a coarse-grained classification (see the {@code *_NAT} and
 * related constants in this class). The {@link #publicAddress} field represents a single detected
 * public address. The {@link #getMtu()} value is an advisory MTU in bytes: it defaults to {@link
 * #DEFAULT_MTU} and may be adjusted by the detector if it has more accurate information.
 *
 * <ul>
 *   <li><b>Mutability:</b> {@link #publicAddress} and {@link #natType} are immutable; MTU is
 *       mutable.
 *   <li><b>Thread-safety:</b> instances are safe to share after construction if MTU is not mutated,
 *       otherwise external synchronization is required.
 * </ul>
 *
 * @see InetAddress
 */
public class DetectedIP {

  /**
   * Detected externally visible address for this host, used as a public contact address.
   *
   * <p>This value is expected to be non-null and represent an address that other peers can route to
   * from outside the local network. The exact detection strategy is plugin-defined; callers should
   * treat this field as a best-effort hint rather than a guarantee of reachability.
   */
  public final InetAddress publicAddress;

  /**
   * Classified NAT and UDP reachability type for this host, as reported by the detector plugin.
   *
   * <p>This value should normally be one of the {@code *_NAT}, {@link #FULL_INTERNET}, {@link
   * #NO_UDP}, or {@link #NOT_SUPPORTED} constants in this class. It is intentionally coarse and is
   * used for policy decisions (e.g., whether inbound UDP is plausible), not for fine-grained
   * diagnostics.
   */
  public final short natType;

  /**
   * Default MTU used when no better information is available, in bytes.
   *
   * <p>This value is used as a conservative baseline when the detector cannot determine an
   * interface-specific MTU. It is advisory only and does not guarantee that a given path can carry
   * packets of this size without fragmentation.
   */
  public static final int DEFAULT_MTU = 1500;

  /** The MTU as advertised by the JVM. */
  private int mtu;

  // Constants
  /**
   * The detector plugin does not support determining the NAT/reachability type.
   *
   * <p>Callers should interpret this as "unknown" rather than as a specific NAT behavior. When this
   * value is reported, higher-level code typically falls back to conservative defaults or
   * alternative heuristics.
   */
  public static final short NOT_SUPPORTED = 1;

  /**
   * Full inbound reachability without NAT restrictions (best-effort classification).
   *
   * <p>This indicates that inbound UDP traffic is expected to work without NAT traversal based on
   * the detector's observations. It does not imply that all ports are open or that connectivity is
   * guaranteed under all network conditions.
   */
  public static final short FULL_INTERNET = 2;

  /**
   * Full cone NAT. Once we have sent a packet out on a port, any node anywhere can send us a packet
   * on that port. The nicest option, but very rare, unfortunately.
   *
   * <p>This classification is typically used to decide whether simple outbound traffic is
   * sufficient to enable inbound peer communication without additional coordination.
   */
  public static final short FULL_CONE_NAT = 3;

  /**
   * Restricted cone NAT. Once we have sent a packet out to a specific IP, it can send us packets on
   * the port we just used.
   *
   * <p>This indicates that a prior outbound packet to a given peer is a prerequisite for receiving
   * inbound traffic from that peer's address.
   */
  public static final short RESTRICTED_CONE_NAT = 4;

  /**
   * Port restricted cone NAT. Once we have sent a packet to a specific IP+Port, that IP+Port can
   * send us packets on the port we just used.
   *
   * <p>This is more restrictive than {@link #RESTRICTED_CONE_NAT} and implies that both the remote
   * address and remote port must match the observed outbound mapping.
   */
  public static final short PORT_RESTRICTED_NAT = 5;

  /**
   * Symmetric NAT. Uses a separate port number for each IP+port.
   *
   * <p>This classification is commonly treated as difficult for unsolicited inbound traffic,
   * especially when both sides exhibit symmetric behavior, because mappings may depend on the
   * remote endpoint.
   */
  public static final short SYMMETRIC_NAT = 6;

  /**
   * Symmetric UDP firewall: no NAT, but inbound filtering behaves similarly to symmetric NAT.
   *
   * <p>This is used to distinguish filtering behavior from address translation. Like {@link
   * #SYMMETRIC_NAT}, it generally implies that successful inbound communication may require prior
   * outbound traffic to the same endpoint.
   */
  public static final short SYMMETRIC_UDP_FIREWALL = 7;

  /**
   * No UDP connectivity is available (best-effort classification).
   *
   * <p>When reported, higher-level code should avoid relying on UDP reachability. This value does
   * not specify the underlying reason (e.g., local policy, firewalling, or network failure); it
   * only records the detector's observed outcome.
   */
  public static final short NO_UDP = 8;

  /**
   * Creates a new detection result with the given public address and NAT classification.
   *
   * <p>The created instance uses {@link #DEFAULT_MTU} until {@link #setMtu(int)} is called. This
   * constructor does not validate inputs; callers are expected to pass a non-null {@code addr} and
   * a {@code type} that matches one of the documented constants (or a plugin-specific value when
   * operating out of tree).
   *
   * @param addr externally visible {@link InetAddress}; must be non-null for correct behavior
   * @param type NAT/reachability classification; typically one of this class's {@code short}
   *     constants
   */
  public DetectedIP(InetAddress addr, short type) {
    this.publicAddress = addr;
    this.natType = type;
    this.mtu = DEFAULT_MTU;
  }

  /**
   * Returns the advisory MTU for outbound packets, in bytes.
   *
   * <p>This value is a hint that may be used when selecting packet sizes to reduce fragmentation.
   * It defaults to {@link #DEFAULT_MTU}. No validation is performed when the value is set; callers
   * should treat values less than or equal to zero as invalid input from upstream detectors.
   *
   * @return the current MTU hint in bytes, defaulting to {@link #DEFAULT_MTU} when unknown
   */
  public int getMtu() {
    return mtu;
  }

  /**
   * Sets the advisory MTU for outbound packets, in bytes.
   *
   * <p>This is intended for detector implementations that can infer a more accurate MTU than the
   * JVM default. The value is stored as-is; callers should provide a positive byte count and avoid
   * mutating the MTU concurrently with reads unless they apply external synchronization.
   *
   * @param mtu MTU hint in bytes; expected to be a positive value, though not validated here
   */
  public void setMtu(int mtu) {
    this.mtu = mtu;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof DetectedIP d)) {
      return false;
    }
    return ((d.natType == natType) && d.publicAddress.equals(publicAddress));
  }

  @Override
  public int hashCode() {
    return publicAddress.hashCode() ^ natType;
  }

  @Override
  public String toString() {
    return publicAddress.toString() + ":" + natType + ":" + mtu;
  }
}
