package network.crypta.io;

import static org.junit.Assert.*;

import java.net.InetAddress;
import org.junit.Test;

/**
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id: Inet4AddressMatcherTest.java 10490 2006-09-20 00:07:46Z toad $
 */
public class Inet4AddressMatcherTest {

  @Test
  public void test() throws Exception {
    Inet4AddressMatcher matcher = new Inet4AddressMatcher("192.168.1.2");
    assertFalse(matcher.matches(InetAddress.getByName("192.168.1.1")));
    assertTrue(matcher.matches(InetAddress.getByName("192.168.1.2")));
    assertFalse(matcher.matches(InetAddress.getByName("127.0.0.1")));
    assertFalse(matcher.matches(InetAddress.getByName("0.0.0.0")));

    matcher = new Inet4AddressMatcher("192.168.1.2/8");
    assertTrue(matcher.matches(InetAddress.getByName("192.168.1.1")));
    assertTrue(matcher.matches(InetAddress.getByName("192.168.1.2")));
    assertTrue(matcher.matches(InetAddress.getByName("192.168.2.1")));
    assertTrue(matcher.matches(InetAddress.getByName("192.16.81.1")));
    assertTrue(matcher.matches(InetAddress.getByName("192.255.255.255")));
    assertFalse(matcher.matches(InetAddress.getByName("172.16.1.1")));
    assertFalse(matcher.matches(InetAddress.getByName("127.0.0.1")));
    assertFalse(matcher.matches(InetAddress.getByName("0.0.0.0")));
    assertTrue(matcher.matches(InetAddress.getByName("192.0.0.0")));

    /* some fancy matching */
    matcher = new Inet4AddressMatcher("192.168.1.1/255.0.255.0");
    assertTrue(matcher.matches(InetAddress.getByName("192.168.1.1")));
    assertTrue(matcher.matches(InetAddress.getByName("192.16.1.1")));
    assertFalse(matcher.matches(InetAddress.getByName("192.168.2.1")));
    assertFalse(matcher.matches(InetAddress.getByName("192.16.2.1")));
    assertFalse(matcher.matches(InetAddress.getByName("127.0.0.1")));

    matcher = new Inet4AddressMatcher("127.0.0.1/8");
    assertTrue(matcher.matches(InetAddress.getByName("127.0.0.1")));
    assertTrue(matcher.matches(InetAddress.getByName("127.23.42.64")));
    assertTrue(matcher.matches(InetAddress.getByName("127.0.0.0")));
    assertTrue(matcher.matches(InetAddress.getByName("127.255.255.255")));
    assertFalse(matcher.matches(InetAddress.getByName("28.0.0.1")));

    matcher = new Inet4AddressMatcher("0.0.0.0/0");
    assertTrue(matcher.matches(InetAddress.getByName("127.0.0.1")));
    assertTrue(matcher.matches(InetAddress.getByName("192.168.1.1")));
    assertTrue(matcher.matches(InetAddress.getByName("192.168.2.1")));
    assertTrue(matcher.matches(InetAddress.getByName("172.16.42.23")));
    assertTrue(matcher.matches(InetAddress.getByName("10.0.0.1")));
    assertTrue(matcher.matches(InetAddress.getByName("224.0.0.1")));
  }
}
