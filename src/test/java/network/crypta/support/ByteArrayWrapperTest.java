package network.crypta.support;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for {@link ByteArrayWrapper}.
 *
 * <p>Covers equality, hashing, defensive copying, natural ordering, and the FAST_COMPARATOR.
 */
class ByteArrayWrapperTest {

  @Test
  void constructor_whenNull_throwsNPE() {
    assertThrows(NullPointerException.class, () -> new ByteArrayWrapper(null));
  }

  @Test
  void constructor_whenArrayMutatedLater_internalCopyUnaffected() {
    byte[] original = new byte[] {1, 2, 3, 4};
    ByteArrayWrapper wrapper = new ByteArrayWrapper(original);

    original[0] = 9; // mutate caller-owned array

    assertEquals(new ByteArrayWrapper(new byte[] {1, 2, 3, 4}), wrapper);
  }

  @Test
  void get_returnsDefensiveCopy() {
    byte[] data = new byte[] {10, 20, 30};
    ByteArrayWrapper wrapper = new ByteArrayWrapper(data);

    byte[] copy = wrapper.get();
    assertArrayEquals(data, copy);

    // Mutating the returned array must not affect the wrapper's content
    copy[0] = 99;
    assertEquals(new ByteArrayWrapper(new byte[] {10, 20, 30}), wrapper);
  }

  @Test
  void equals_whenSameContent_expectTrue() {
    byte[] a = "alpha".getBytes(StandardCharsets.UTF_8);
    ByteArrayWrapper w1 = new ByteArrayWrapper(a);
    ByteArrayWrapper w2 = new ByteArrayWrapper(a.clone());
    assertEquals(w1, w2);
    assertEquals(w1.hashCode(), w2.hashCode());
  }

  @Test
  void equals_whenDifferentContentOrType_expectFalse() {
    ByteArrayWrapper w1 = new ByteArrayWrapper(new byte[] {1, 2});
    ByteArrayWrapper w2 = new ByteArrayWrapper(new byte[] {1, 3});
    assertNotEquals(w2, w1);
    // Ensure ByteArrayWrapper#equals(Object) is exercised (avoid static type mismatch warnings)
    Object other = "not-a-wrapper";
    assertNotEquals(other, w1);
  }

  @Test
  void equals_symmetricAndTransitive() {
    byte[] data = new byte[] {7, 7, 7};
    ByteArrayWrapper a = new ByteArrayWrapper(data);
    ByteArrayWrapper b = new ByteArrayWrapper(data.clone());
    ByteArrayWrapper c = new ByteArrayWrapper(data.clone());

    // symmetric
    assertEquals(a, b);
    assertEquals(b, a);
    // transitive
    assertEquals(a, b);
    assertEquals(b, c);
    assertEquals(a, c);
  }

  @Test
  @SuppressWarnings("SelfComparison")
  void compareTo_sameInstance_returnsZero() {
    ByteArrayWrapper w = new ByteArrayWrapper(new byte[] {1, 2, 3});
    //noinspection EqualsWithItself
    assertEquals(0, w.compareTo(w));
  }

  @Test
  void compareTo_equalArrays_returnsZero() {
    byte[] a = new byte[] {1, 2, 3};
    ByteArrayWrapper w1 = new ByteArrayWrapper(a);
    ByteArrayWrapper w2 = new ByteArrayWrapper(a.clone());
    assertEquals(0, w1.compareTo(w2));
  }

  @Test
  void compareTo_prefixShorterIsLess() {
    ByteArrayWrapper shorter = new ByteArrayWrapper(new byte[] {1, 2});
    ByteArrayWrapper longer = new ByteArrayWrapper(new byte[] {1, 2, 0});
    // shorter should be less (prefix) according to Fields.compareBytes
    int cmp = shorter.compareTo(longer);
    // Expect negative (shorter < longer)
    assertEquals(-1, Integer.signum(cmp));
  }

  @Test
  void compareTo_usesUnsignedByteOrder() {
    // -1 (0xFF) should be greater than 1 (0x01) when treated as unsigned
    ByteArrayWrapper negative = new ByteArrayWrapper(new byte[] {(byte) 0xFF});
    ByteArrayWrapper positive = new ByteArrayWrapper(new byte[] {0x01});
    int cmp = negative.compareTo(positive);
    assertEquals(1, Integer.signum(cmp));
  }

  @Test
  void fastComparator_whenEqual_expectZeroAndConsistentWithEquals() {
    byte[] data = new byte[] {42, 43, 44};
    ByteArrayWrapper a = new ByteArrayWrapper(data);
    ByteArrayWrapper b = new ByteArrayWrapper(data.clone());
    assertEquals(0, ByteArrayWrapper.FAST_COMPARATOR.compare(a, b));
    assertEquals(a, b);
  }

  @Test
  void fastComparator_sortsDeterministically() {
    // Build a small, diverse set to exercise hash and natural order
    List<ByteArrayWrapper> list = new ArrayList<>();
    list.add(new ByteArrayWrapper(new byte[] {0}));
    list.add(new ByteArrayWrapper(new byte[] {1}));
    list.add(new ByteArrayWrapper(new byte[] {(byte) 0xFF}));
    list.add(new ByteArrayWrapper(new byte[] {1, 2}));
    list.add(new ByteArrayWrapper(new byte[] {1, 2, 3}));
    list.add(new ByteArrayWrapper("alpha".getBytes(StandardCharsets.UTF_8)));
    list.add(new ByteArrayWrapper("beta".getBytes(StandardCharsets.UTF_8)));

    // Sort with FAST_COMPARATOR
    list.sort(ByteArrayWrapper.FAST_COMPARATOR);

    // Validate comparator contract: comparator returns 0 iff equals()
    for (int i = 0; i < list.size(); i++) {
      for (ByteArrayWrapper byteArrayWrapper : list) {
        int cmp = ByteArrayWrapper.FAST_COMPARATOR.compare(list.get(i), byteArrayWrapper);
        if (cmp == 0) {
          assertEquals(list.get(i), byteArrayWrapper);
        }
      }
    }

    // Also check the order is consistent with applying the same rule explicitly
    List<ByteArrayWrapper> expected = new ArrayList<>(list);
    expected.sort(
        Comparator.comparingInt(ByteArrayWrapper::hashCode)
            .thenComparing(ByteArrayWrapper::compareTo));
    assertEquals(expected, list);
  }

  @Test
  void equalsAndHashCode_whenUsedAsMapKey_correctBehavior() {
    byte[] data1 =
        "asldkjaskjdsakdhasdhaskjdhaskjhbkasbhdjkasbduiwbxgdoudgboewuydxbybuewyxbuewyuwe"
            .getBytes(StandardCharsets.UTF_8);
    byte[] data2 = "string2".getBytes(StandardCharsets.UTF_8);

    ByteArrayWrapper wrapper1 = new ByteArrayWrapper(data1);
    ByteArrayWrapper wrapper2 = new ByteArrayWrapper(data1.clone());
    ByteArrayWrapper wrapper3 = new ByteArrayWrapper(data2);

    // Sanity: equals/hash
    assertEquals(wrapper2, wrapper1);
    assertNotEquals(wrapper3, wrapper2);
    // Ensure ByteArrayWrapper#equals(Object) is the method under test
    Object other = "";
    assertNotEquals(other, wrapper1);

    Map<ByteArrayWrapper, ByteArrayWrapper> map = new HashMap<>();
    map.put(wrapper1, wrapper1);
    map.put(wrapper2, wrapper2); // should replace value for equal key
    map.put(wrapper3, wrapper3);

    Object o1 = map.get(wrapper1);
    Object o2 = map.get(wrapper2);
    Object o3 = map.get(wrapper3);

    assertEquals(o1, o2); // equal keys resolve to the same map entry
    assertNotSame(o1, wrapper1); // value replaced by later put
    assertSame(o1, wrapper2); // last value remains
    assertSame(o3, wrapper3); // distinct key unaffected
  }
}
