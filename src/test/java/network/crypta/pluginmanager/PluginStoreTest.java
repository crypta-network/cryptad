package network.crypta.pluginmanager;

import java.util.Map;
import network.crypta.node.FSParseException;
import network.crypta.support.Base64;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PluginStoreTest {

  @Test
  void exportStoreAsSFS_whenEmptyStore_expectRoundTripEmpty()
      throws IllegalBase64Exception, FSParseException {
    // Arrange
    PluginStore store = new PluginStore();

    // Act
    SimpleFieldSet exported = store.exportStoreAsSFS();
    PluginStore rehydrated = new PluginStore(exported);

    // Assert
    assertTrue(rehydrated.subStores.isEmpty());
    assertTrue(rehydrated.longs.isEmpty());
    assertTrue(rehydrated.longsArrays.isEmpty());
    assertTrue(rehydrated.integers.isEmpty());
    assertTrue(rehydrated.integersArrays.isEmpty());
    assertTrue(rehydrated.shorts.isEmpty());
    assertTrue(rehydrated.shortsArrays.isEmpty());
    assertTrue(rehydrated.booleans.isEmpty());
    assertTrue(rehydrated.booleansArrays.isEmpty());
    assertTrue(rehydrated.bytes.isEmpty());
    assertTrue(rehydrated.bytesArrays.isEmpty());
    assertTrue(rehydrated.strings.isEmpty());
    assertTrue(rehydrated.stringsArrays.isEmpty());
  }

  @Test
  void exportStoreAsSFS_whenStoreHasAllTypes_expectRoundTripPreservesData()
      throws IllegalBase64Exception, FSParseException {
    // Arrange
    PluginStore store = buildStoreWithAllTypes();

    // Act
    SimpleFieldSet exported = store.exportStoreAsSFS();
    PluginStore rehydrated = new PluginStore(exported);

    // Assert
    assertEquals(store.longs, rehydrated.longs);
    assertLongArrayMapEquals(store.longsArrays, rehydrated.longsArrays);
    assertEquals(store.integers, rehydrated.integers);
    assertIntArrayMapEquals(store.integersArrays, rehydrated.integersArrays);
    assertEquals(store.shorts, rehydrated.shorts);
    assertShortArrayMapEquals(store.shortsArrays, rehydrated.shortsArrays);
    assertEquals(store.booleans, rehydrated.booleans);
    assertBooleanArrayMapEquals(store.booleansArrays, rehydrated.booleansArrays);
    assertEquals(store.bytes, rehydrated.bytes);
    assertByteArrayMapEquals(store.bytesArrays, rehydrated.bytesArrays);
    assertEquals(store.strings, rehydrated.strings);
    assertStringArrayMapEquals(store.stringsArrays, rehydrated.stringsArrays);
  }

  @Test
  void exportStoreAsSFS_whenStringArraysContainInvalidChars_expectRoundTripPreservesValues()
      throws IllegalBase64Exception, FSParseException {
    // Arrange
    PluginStore store = new PluginStore();
    String key = "strings" + invalidCharsForSfs();
    String[] values =
        new String[] {"value\nwith\nnewlines", "value=with=equals", "value;with;semicolons"};
    store.stringsArrays.put(key, values);

    // Act
    PluginStore rehydrated = new PluginStore(store.exportStoreAsSFS());

    // Assert
    assertArrayEquals(values, rehydrated.stringsArrays.get(key));
  }

  @Test
  void exportStoreAsSFS_whenPrimitiveArrayEmpty_expectEntryDropped()
      throws IllegalBase64Exception, FSParseException {
    // Arrange
    PluginStore store = new PluginStore();
    store.longsArrays.put("empty", new long[0]);

    // Act
    PluginStore rehydrated = new PluginStore(store.exportStoreAsSFS());

    // Assert
    assertTrue(rehydrated.longsArrays.isEmpty());
  }

  @Test
  void pluginStore_whenKeyIsNotBase64_expectIllegalBase64Exception() {
    // Arrange
    SimpleFieldSet fs = new SimpleFieldSet(true, true);
    fs.put("long.A", 1L);

    // Act + Assert
    assertThrows(IllegalBase64Exception.class, () -> new PluginStore(fs));
  }

  @Test
  void pluginStore_whenNumericValueInvalid_expectFSParseException() {
    // Arrange
    SimpleFieldSet fs = new SimpleFieldSet(true, true);
    String encodedKey = Base64.encodeUTF8("long-key");
    fs.putSingle("long." + encodedKey, "not-a-number");

    // Act + Assert
    assertThrows(FSParseException.class, () -> new PluginStore(fs));
  }

  @Test
  void pluginStore_whenSubStorePresent_expectSubStoreLoaded()
      throws IllegalBase64Exception, FSParseException {
    // Arrange
    PluginStore child = new PluginStore();
    child.integers.put("nested", 12);
    String encodedKey = Base64.encodeUTF8("child");
    SimpleFieldSet substoreGroup = new SimpleFieldSet(true, true);
    substoreGroup.put(encodedKey, child.exportStoreAsSFS());
    SimpleFieldSet root = new SimpleFieldSet(true, true);
    root.put("substore", substoreGroup);

    // Act
    PluginStore store = new PluginStore(root);

    // Assert
    PluginStore rehydratedChild = store.subStores.get("child");
    assertNotNull(rehydratedChild);
    assertEquals(12, rehydratedChild.integers.get("nested"));
  }

  private static PluginStore buildStoreWithAllTypes() {
    PluginStore store = new PluginStore();
    String invalidKey = "key" + invalidCharsForSfs() + "suffix";
    store.longs.put("longs-key", 42L);
    store.longs.put(invalidKey, Long.MIN_VALUE);
    store.longsArrays.put("longs-array", new long[] {1L, -2L, Long.MAX_VALUE});
    store.longsArrays.put(invalidKey, new long[] {4L});
    store.integers.put("ints-key", 7);
    store.integers.put(invalidKey, Integer.MIN_VALUE);
    store.integersArrays.put("ints-array", new int[] {0, 1, -1, Integer.MAX_VALUE});
    store.integersArrays.put(invalidKey, new int[] {5});
    store.shorts.put("shorts-key", (short) 12);
    store.shorts.put(invalidKey, Short.MIN_VALUE);
    store.shortsArrays.put("shorts-array", new short[] {(short) 1, (short) -2});
    store.shortsArrays.put(invalidKey, new short[] {(short) 3});
    store.booleans.put("bool-key", true);
    store.booleans.put(invalidKey, false);
    store.booleansArrays.put("bools-array", new boolean[] {true, false, true});
    store.booleansArrays.put(invalidKey, new boolean[] {false});
    store.bytes.put("bytes-key", (byte) 5);
    store.bytes.put(invalidKey, (byte) -1);
    store.bytesArrays.put("bytes-array", new byte[] {1, 2, 3, 4});
    store.bytesArrays.put(invalidKey, new byte[] {9});
    store.strings.put("strings-key", "value");
    store.strings.put(invalidKey, "value" + invalidCharsForSfs());
    store.stringsArrays.put("strings-array", new String[] {"alpha", "beta"});
    store.stringsArrays.put(invalidKey, new String[] {"gamma", "delta"});
    return store;
  }

  private static void assertLongArrayMapEquals(
      Map<String, long[]> expected, Map<String, long[]> actual) {
    assertEquals(expected.size(), actual.size());
    for (Map.Entry<String, long[]> entry : expected.entrySet()) {
      assertTrue(actual.containsKey(entry.getKey()));
      assertArrayEquals(entry.getValue(), actual.get(entry.getKey()));
    }
  }

  private static void assertIntArrayMapEquals(
      Map<String, int[]> expected, Map<String, int[]> actual) {
    assertEquals(expected.size(), actual.size());
    for (Map.Entry<String, int[]> entry : expected.entrySet()) {
      assertTrue(actual.containsKey(entry.getKey()));
      assertArrayEquals(entry.getValue(), actual.get(entry.getKey()));
    }
  }

  private static void assertShortArrayMapEquals(
      Map<String, short[]> expected, Map<String, short[]> actual) {
    assertEquals(expected.size(), actual.size());
    for (Map.Entry<String, short[]> entry : expected.entrySet()) {
      assertTrue(actual.containsKey(entry.getKey()));
      assertArrayEquals(entry.getValue(), actual.get(entry.getKey()));
    }
  }

  private static void assertBooleanArrayMapEquals(
      Map<String, boolean[]> expected, Map<String, boolean[]> actual) {
    assertEquals(expected.size(), actual.size());
    for (Map.Entry<String, boolean[]> entry : expected.entrySet()) {
      assertTrue(actual.containsKey(entry.getKey()));
      assertArrayEquals(entry.getValue(), actual.get(entry.getKey()));
    }
  }

  private static void assertByteArrayMapEquals(
      Map<String, byte[]> expected, Map<String, byte[]> actual) {
    assertEquals(expected.size(), actual.size());
    for (Map.Entry<String, byte[]> entry : expected.entrySet()) {
      assertTrue(actual.containsKey(entry.getKey()));
      assertArrayEquals(entry.getValue(), actual.get(entry.getKey()));
    }
  }

  private static void assertStringArrayMapEquals(
      Map<String, String[]> expected, Map<String, String[]> actual) {
    assertEquals(expected.size(), actual.size());
    for (Map.Entry<String, String[]> entry : expected.entrySet()) {
      assertTrue(actual.containsKey(entry.getKey()));
      assertArrayEquals(entry.getValue(), actual.get(entry.getKey()));
    }
  }

  private static String invalidCharsForSfs() {
    return "\r\n"
        + SimpleFieldSet.KEYVALUE_SEPARATOR_CHAR
        + SimpleFieldSet.MULTI_LEVEL_CHAR
        + SimpleFieldSet.MULTI_VALUE_CHAR;
  }
}
