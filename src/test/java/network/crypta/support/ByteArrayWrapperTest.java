package network.crypta.support;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

/**
 * Test case for {@link ByteArrayWrapper} class.
 *
 * @author stuart martin &lt;wavey@freenetproject.org&gt;
 */
public class ByteArrayWrapperTest {

  private static final String DATA_STRING_1 =
      "asldkjaskjdsakdhasdhaskjdhaskjhbkasbhdjkasbduiwbxgdoudgboewuydxbybuewyxbuewyuwe";

  private static final String DATA_STRING_2 = "string2";

  @Test
  public void testWrapper() {

    byte[] data1 = DATA_STRING_1.getBytes();
    byte[] data2 = DATA_STRING_2.getBytes();

    ByteArrayWrapper wrapper1 = new ByteArrayWrapper(data1);
    ByteArrayWrapper wrapper2 = new ByteArrayWrapper(data1);
    ByteArrayWrapper wrapper3 = new ByteArrayWrapper(data2);

    assertEquals(wrapper1, wrapper2);
    assertEquals(wrapper1, wrapper2);
    assertNotEquals(wrapper2, wrapper3);
    assertNotEquals("", wrapper1);

    Map<ByteArrayWrapper, ByteArrayWrapper> map = new HashMap<>();

    map.put(wrapper1, wrapper1);
    map.put(wrapper2, wrapper2); // should clobber 1 by hashcode
    map.put(wrapper3, wrapper3);

    Object o1 = map.get(wrapper1);
    Object o2 = map.get(wrapper2);
    Object o3 = map.get(wrapper3);

    assertEquals(o1, o2); // are wrapper1 and wrapper2 considered equivalent by hashcode?
    assertNotSame(o1, wrapper1); // did wrapper1 survive?
    assertSame(o1, wrapper2); // did wrapper1 get replaced by 2?
    assertSame(o3, wrapper3); // did wrapper3 get returned by hashcode correctly?
  }
}
