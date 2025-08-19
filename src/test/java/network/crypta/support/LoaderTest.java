package network.crypta.support;

import static org.junit.Assert.*;

import java.lang.reflect.InvocationTargetException;
import org.junit.Test;

/**
 * Test case for {@link Loader} class.
 *
 * @author stuart martin &lt;wavey@freenetproject.org&gt;
 */
public class LoaderTest {

  @Test
  public void testLoader() {
    Object o = null;

    try {
      o = Loader.getInstance("java.lang.String");
    } catch (InvocationTargetException e) {
      fail("unexpected exception" + e.getMessage());
    } catch (NoSuchMethodException e) {
      fail("unexpected exception" + e.getMessage());
    } catch (InstantiationException e) {
      fail("unexpected exception" + e.getMessage());
    } catch (IllegalAccessException e) {
      fail("unexpected exception" + e.getMessage());
    } catch (ClassNotFoundException e) {
      fail("unexpected exception" + e.getMessage());
    }

    assertTrue(o instanceof java.lang.String);
  }
}
