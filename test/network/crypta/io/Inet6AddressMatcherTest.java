package network.crypta.io;

import static org.junit.Assert.*;

import java.net.InetAddress;

import network.crypta.io.Inet6AddressMatcher;
import org.junit.Test;

/**
 * Test case for the {@link Inet6AddressMatcher} class. Contains some
 * very basic tests. Feel free to add more complicated tests!
 * 
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id: Inet6AddressMatcherTest.java 10490 2006-09-20 00:07:46Z toad $
 */
public class Inet6AddressMatcherTest {

	@Test
	public void test() throws Exception {
		Inet6AddressMatcher matcher = new Inet6AddressMatcher("0:0:0:0:0:0:0:0/0");
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:203:dff:fe22:420f")));

		matcher = new Inet6AddressMatcher("fe80:0:0:0:203:dff:fe22:420f/64");
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:203:dff:fe22:420f")));
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:0203:0dff:fe22:420f")));
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:0204:0dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("fe81:0:0:0:0203:0dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("0:0:0:0:0:0:0:1")));
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:0:0:0:1")));

		matcher = new Inet6AddressMatcher("fe80:0:0:0:203:dff:fe22:420f/ffff:ffff:ffff:ffff:0:0:0:0");
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:203:dff:fe22:420f")));
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:0203:0dff:fe22:420f")));
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:0204:0dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("fe81:0:0:0:0203:0dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("0:0:0:0:0:0:0:1")));
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:0:0:0:1")));

		matcher = new Inet6AddressMatcher("fe80:0:0:0:203:dff:fe22:420f/128");
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:203:dff:fe22:420f")));
		assertTrue(matcher.matches(InetAddress.getByName("fe80:0:0:0:0203:0dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("fe80:0:0:0:0204:0dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("fe81:0:0:0:0203:0dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("0:0:0:0:0:0:0:1")));
		assertFalse(matcher.matches(InetAddress.getByName("fe80:0:0:0:0:0:0:1")));

		matcher = new Inet6AddressMatcher("::/0");
		assertTrue(matcher.matches(InetAddress.getByName("fe80::203:dff:fe22:420f")));

		matcher = new Inet6AddressMatcher("fe80::/64");
		assertTrue(matcher.matches(InetAddress.getByName("fe80::203:dff:fe22:420f")));
		assertFalse(matcher.matches(InetAddress.getByName("fe80:203::dff:fe22:420f")));
		
		matcher = new Inet6AddressMatcher("1::fe80/64");
		assertFalse(matcher.matches(InetAddress.getByName("::")));
		assertFalse(matcher.matches(InetAddress.getByName("1::2:3:4:5:6:7")));
		assertFalse(matcher.matches(InetAddress.getByName("1::2:3:4:5:6")));
		assertTrue(matcher.matches(InetAddress.getByName("1::2:3:4:5")));
		assertTrue(matcher.matches(InetAddress.getByName("1::2:3:4")));
		assertTrue(matcher.matches(InetAddress.getByName("1::2:3")));
		assertTrue(matcher.matches(InetAddress.getByName("1::2")));
		assertTrue(matcher.matches(InetAddress.getByName("1::")));
		assertFalse(matcher.matches(InetAddress.getByName("1:2::3:4:5:6:7")));

		assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher("192.168.1.1"));
		assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher("1::2::3"));
		assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher("::1::2"));
		assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher("::1:2:3:4:5:6:7:8"));
		assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher(":1:2:3:4:5:6:7"));
		assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher("1:2:3:4:5:6:7:"));
		assertThrows(IllegalArgumentException.class, () -> new Inet6AddressMatcher("123456::789abcde"));
		assertTrue(Inet6AddressMatcher.matches("::1", InetAddress.getByName("::1")));
		assertTrue(Inet6AddressMatcher.matches("fe80::", InetAddress.getByName("fe80::")));
	}

}
