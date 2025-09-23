package network.crypta.support;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Test case for {@link MutableBoolean} class.
 *
 * @author stuart martin &lt;wavey@freenetproject.org&gt;
 */
public class MutableBooleanTest {

  @Test
  public void testMutableBoolean() {

    MutableBoolean bool = new MutableBoolean();
    bool.value = false;

    assertFalse(bool.value);

    bool.value = true;

    assertTrue(bool.value);
  }
}
