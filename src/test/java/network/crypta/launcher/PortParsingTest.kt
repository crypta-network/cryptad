package network.crypta.launcher

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PortParsingTest {
  @Test
  fun parsesSimpleIPv4() {
    val line = "Starting FProxy on 127.0.0.1:8888"
    assertEquals(8888, parseFProxyPortFromLine(line))
  }

  @Test
  fun parsesIPv6AndIPv4List() {
    val line = "Starting FProxy on 127.0.0.1, [::1]:8080"
    assertEquals(8080, parseFProxyPortFromLine(line))
  }

  @Test
  fun parsesWithTrailingText() {
    val line = "... Starting FProxy on [::1]:12345 ready"
    assertEquals(12345, parseFProxyPortFromLine(line))
  }

  @Test
  fun ignoresNonMatching() {
    assertNull(parseFProxyPortFromLine("Nothing to see here"))
    assertNull(parseFProxyPortFromLine("Starting service on port abc"))
  }
}
