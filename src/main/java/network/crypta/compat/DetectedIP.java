package network.crypta.compat;

import java.net.InetAddress;

/** Compatibility value object for detected external IP information. */
public class DetectedIP {
  public static final int NOT_SUPPORTED = 1;
  public static final int FULL_INTERNET = 2;
  public static final int FULL_CONE_NAT = 3;
  public static final int RESTRICTED_CONE_NAT = 4;
  public static final int PORT_RESTRICTED_NAT = 5;
  public static final int SYMMETRIC_NAT = 6;
  public static final int SYMMETRIC_UDP_FIREWALL = 7;
  public static final int NO_UDP = 8;
  public static final int DEFAULT_MTU = 1500;

  public final InetAddress publicAddress;
  public final int natType;
  private int mtu;

  public DetectedIP(InetAddress publicAddress, int natType) {
    this(publicAddress, natType, DEFAULT_MTU);
  }

  public DetectedIP(InetAddress publicAddress, int natType, int mtu) {
    this.publicAddress = publicAddress;
    this.natType = natType;
    this.mtu = mtu;
  }

  public int getMtu() {
    return mtu;
  }

  public void setMtu(int mtu) {
    this.mtu = mtu;
  }
}
