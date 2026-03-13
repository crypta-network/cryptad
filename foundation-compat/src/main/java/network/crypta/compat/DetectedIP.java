package network.crypta.compat;

import java.net.InetAddress;

/**
 * Compatibility value object carrying externally detected IP and NAT classification data.
 *
 * <p>This type is a small data carrier used at the boundary between detection providers and node
 * networking logic. It bundles three pieces of information: the detected public address, a
 * coarse-grained NAT/UDP reachability category, and an MTU hint used for packet sizing decisions.
 * The NAT constants intentionally retain legacy numeric values so adapters that still emit older
 * codes can interoperate without remapping.
 *
 * <p>Instances are partially mutable: {@link #publicAddress} and {@link #natType} are immutable,
 * while MTU can be updated as better path information becomes available. The class does not enforce
 * semantic validation (for example, null addresses or non-standard NAT codes), so callers should
 * sanitize inputs before using the values for policy decisions.
 *
 * <ul>
 *   <li><b>Primary use:</b> report detector output to reachability classification logic.
 *   <li><b>Trade-off:</b> compatibility-preserving numeric constants over strict type safety.
 * </ul>
 *
 * @see InetAddress
 */
public class DetectedIP {
  /**
   * Legacy code indicating NAT classification is unavailable from the detector.
   *
   * <p>Callers should interpret this as unknown capability rather than an explicit failure mode.
   */
  public static final int NOT_SUPPORTED = 1;

  /**
   * Legacy code indicating direct internet reachability without NAT restrictions.
   *
   * <p>This is the most permissive connectivity class in the compatibility mapping.
   */
  public static final int FULL_INTERNET = 2;

  /**
   * Legacy code for full-cone NAT behavior.
   *
   * <p>After an outbound mapping exists, inbound packets are broadly accepted on that port.
   */
  public static final int FULL_CONE_NAT = 3;

  /**
   * Legacy code for restricted-cone NAT behavior.
   *
   * <p>Inbound packets are accepted only from remote addresses the host has contacted first.
   */
  public static final int RESTRICTED_CONE_NAT = 4;

  /**
   * Legacy code for port-restricted-cone NAT behavior.
   *
   * <p>Inbound packets generally require prior outbound traffic to the same remote address and
   * port.
   */
  public static final int PORT_RESTRICTED_NAT = 5;

  /**
   * Legacy code for symmetric NAT behavior.
   *
   * <p>Mappings may vary per destination endpoint, making unsolicited inbound UDP difficult.
   */
  public static final int SYMMETRIC_NAT = 6;

  /**
   * Legacy code for symmetric UDP firewall behavior.
   *
   * <p>This mirrors symmetric filtering behavior without necessarily implying address translation.
   */
  public static final int SYMMETRIC_UDP_FIREWALL = 7;

  /**
   * Legacy code indicating no usable UDP connectivity was detected.
   *
   * <p>Consumers typically treat this as closed for UDP-based peer reachability.
   */
  public static final int NO_UDP = 8;

  /**
   * Default MTU hint in bytes when no detector-provided value is available.
   *
   * <p>This constant preserves historical compatibility behavior for constructor defaults.
   */
  public static final int DEFAULT_MTU = 1500;

  /**
   * Externally visible address reported by the detection provider.
   *
   * <p>This value is stored as provided and is expected to represent a routable public endpoint.
   */
  public final InetAddress publicAddress;

  /**
   * NAT/reachability classification code using this class's legacy compatibility constants.
   *
   * <p>While typical values come from the predefined constants, non-standard provider codes are not
   * rejected at construction time.
   */
  public final int natType;

  /** Mutable MTU hint in bytes associated with this detection result. */
  private int mtu;

  /**
   * Creates a detection result using the default MTU hint.
   *
   * <p>This constructor preserves compatibility behavior by assigning {@link #DEFAULT_MTU} when a
   * specific MTU is not provided by the caller.
   *
   * @param publicAddress externally detected address associated with this observation
   * @param natType legacy numeric NAT/reachability category for this observation
   */
  public DetectedIP(InetAddress publicAddress, int natType) {
    this(publicAddress, natType, DEFAULT_MTU);
  }

  /**
   * Creates a detection result with an explicit MTU hint.
   *
   * <p>All arguments are stored verbatim to keep this type as a compatibility-focused data carrier.
   * Input validation is intentionally deferred to calling code.
   *
   * @param publicAddress externally detected address associated with this observation
   * @param natType legacy numeric NAT/reachability category for this observation
   * @param mtu MTU hint in bytes, typically a positive path-size estimate
   */
  public DetectedIP(InetAddress publicAddress, int natType, int mtu) {
    this.publicAddress = publicAddress;
    this.natType = natType;
    this.mtu = mtu;
  }

  /**
   * Returns the current MTU hint associated with this detection result.
   *
   * <p>The returned value is advisory and expressed in bytes; callers should treat non-positive
   * values as invalid upstream input if they occur.
   *
   * @return advisory MTU value in bytes currently stored on this instance
   */
  public int getMtu() {
    return mtu;
  }

  /**
   * Updates the MTU hint associated with this detection result.
   *
   * <p>This mutator allows downstream components to refine MTU estimates after additional probing
   * while keeping address and NAT classification immutable.
   *
   * @param mtu advisory MTU value in bytes to store on this instance
   */
  public void setMtu(int mtu) {
    this.mtu = mtu;
  }
}
