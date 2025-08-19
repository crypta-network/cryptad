package network.crypta.config;

import static org.junit.Assert.*;

import network.crypta.test.UTFUtil;
import org.junit.Before;
import org.junit.Test;

/**
 * Test case for the {@link Config} class.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class ConfigTest {
  @Before
  public void setUp() throws Exception {
    conf = new Config();
    sc = conf.createSubConfig("testing");
  }

  @Test
  public void testConfig() {
    assertNotNull(new Config());
  }

  @Test
  public void testRegister() {
    /* test if we can register */
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < UTFUtil.PRINTABLE_ASCII.length; i++) {
      sb.append(UTFUtil.PRINTABLE_ASCII[i]);
    }
    for (int i = 0; i < UTFUtil.STRESSED_UTF.length; i++) {
      sb.append(UTFUtil.STRESSED_UTF[i]);
    }
    assertNotNull(conf.createSubConfig(sb.toString()));

    /* test if it prevents multiple registrations */
    try {
      conf.register(sc);
    } catch (IllegalArgumentException ie) {
      return;
    }
    fail();
  }

  @Test
  public void testGetConfigs() {
    assertNotNull(conf.getConfigs());
    assertNotEquals(new Config().getConfigs(), conf);
    assertEquals(1, conf.getConfigs().length);
    assertSame(sc, conf.getConfigs()[0]);
  }

  @Test
  public void testGet() {
    assertSame(sc, conf.get("testing"));
  }

  Config conf;
  SubConfig sc;
}
