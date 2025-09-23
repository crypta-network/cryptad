package network.crypta.io;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;
import network.crypta.io.AddressIdentifier.AddressType;
import network.crypta.support.Logger;

/** Implementation of allowedHosts */
public class AllowedHosts {

  protected final List<AddressMatcher> addressMatchers = new ArrayList<>();

  public AllowedHosts(String allowedHosts) {
    setAllowedHosts(allowedHosts);
  }

  /**
   * Sets the list of allowed hosts to <code>allowedHosts</code>. The new list is in effect
   * immediately after this method has finished.
   *
   * @param allowedHosts The new list of allowed hosts s
   */
  public void setAllowedHosts(String allowedHosts) {
    if (allowedHosts == null || allowedHosts.isEmpty())
      allowedHosts = NetworkInterface.DEFAULT_BIND_TO;
    StringTokenizer allowedHostsTokens = new StringTokenizer(allowedHosts, ",");
    List<AddressMatcher> newAddressMatchers = new ArrayList<>();
    while (allowedHostsTokens.hasMoreTokens()) {
      String allowedHost = allowedHostsTokens.nextToken().trim();
      String hostname = allowedHost;
      if (allowedHost.indexOf('/') != -1) {
        hostname = allowedHost.substring(0, allowedHost.indexOf('/'));
      }
      AddressType addressType = AddressIdentifier.getAddressType(hostname);
      if (addressType == AddressType.IPv4) {
        newAddressMatchers.add(new Inet4AddressMatcher(allowedHost));
      } else if (addressType == AddressType.IPv6) {
        newAddressMatchers.add(new Inet6AddressMatcher(allowedHost));
      } else if (allowedHost.equals("*")) {
        newAddressMatchers.add(new EverythingMatcher());
      } else {
        Logger.error(NetworkInterface.class, "Ignoring invalid allowedHost: " + allowedHost);
      }
    }
    synchronized (this) {
      this.addressMatchers.clear();
      this.addressMatchers.addAll(newAddressMatchers);
    }
  }

  public boolean allowed(InetAddress clientAddress) {
    AddressType clientAddressType =
        AddressIdentifier.getAddressType(clientAddress.getHostAddress());
    return allowed(clientAddressType, clientAddress);
  }

  public synchronized boolean allowed(AddressType clientAddressType, InetAddress clientAddress) {
    for (AddressMatcher matcher : addressMatchers) {
      if (matcher.matches(clientAddress)) return true;
    }
    return false;
  }

  public synchronized String getAllowedHosts() {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < addressMatchers.size(); i++) {
      AddressMatcher matcher = addressMatchers.get(i);
      if (matcher instanceof EverythingMatcher) return "*";
      if (i != 0) sb.append(',');
      sb.append(matcher.getHumanRepresentation());
    }
    return sb.toString();
  }
}
