package network.crypta.node.stats;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100")
class DataStoreInstanceTypeTest {

  @Test
  @DisplayName("constructor_whenValid_expectFieldsAssigned")
  void constructor_whenValid_expectFieldsAssigned() {
    // Arrange
    DataStoreKeyType key = DataStoreKeyType.CHK;
    DataStoreType store = DataStoreType.STORE;

    // Act
    DataStoreInstanceType instance = new DataStoreInstanceType(key, store);

    // Assert
    assertNotNull(instance);
    assertSame(store, instance.store);
    assertSame(key, instance.key);
  }

  @Test
  @DisplayName("equals_whenSameReference_expectTrue")
  void equals_whenSameReference_expectTrue() {
    // Arrange
    DataStoreInstanceType instance =
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE);

    // Act & Assert
    //noinspection EqualsWithItself
    assertEquals(instance, instance);
  }

  @Test
  @DisplayName("equals_whenNull_expectFalse")
  void equals_whenNull_expectFalse() {
    // Arrange
    DataStoreInstanceType instance =
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE);

    // Act & Assert (does call instance.equals(null) under the hood without Sonar warning)
    assertNotEquals(null, instance);
  }

  // Note: The "different class" behavior is covered by the subclass test below
  // (equals uses getClass() check). A direct equals comparison with a String/Object
  // is avoided to keep SonarLint clean (inconvertible types warning).

  private static class SubType extends DataStoreInstanceType {
    SubType(DataStoreKeyType key, DataStoreType store) {
      super(key, store);
    }
  }

  @Test
  @DisplayName("equals_whenSubclassSameFields_expectFalseDueToClassCheck")
  void equals_whenSubclassSameFields_expectFalseDueToClassCheck() {
    // Arrange
    DataStoreInstanceType base =
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE);
    DataStoreInstanceType sub = new SubType(DataStoreKeyType.CHK, DataStoreType.STORE);

    // Act & Assert
    assertNotEquals(base, sub);
    assertNotEquals(sub, base);
  }

  static Stream<Arguments> allStoreKeyPairs() {
    return Arrays.stream(DataStoreType.values())
        .flatMap(
            store -> Arrays.stream(DataStoreKeyType.values()).map(key -> Arguments.of(store, key)));
  }

  @ParameterizedTest(name = "equals/hashCode with store={0}, key={1}")
  @MethodSource("allStoreKeyPairs")
  @DisplayName("equals_whenSameFields_expectTrueAndHashCodesEqual")
  void equals_whenSameFields_expectTrueAndHashCodesEqual(
      DataStoreType store, DataStoreKeyType key) {
    // Arrange
    DataStoreInstanceType a = new DataStoreInstanceType(key, store);
    DataStoreInstanceType b = new DataStoreInstanceType(key, store);

    // Act & Assert
    assertTrue(a.equals(b) && b.equals(a));
    assertEquals(a.hashCode(), b.hashCode());

    // hashCode consistency
    int first = a.hashCode();
    int second = a.hashCode();
    assertEquals(first, second);
  }

  static Stream<Arguments> sameStore_differentKey() {
    DataStoreType[] stores = DataStoreType.values();
    DataStoreKeyType[] keys = DataStoreKeyType.values();
    return Arrays.stream(stores)
        .flatMap(
            store -> {
              // For each key, pair with the next key (cyclic) to ensure difference
              return IntStream.range(0, keys.length)
                  .mapToObj(
                      index ->
                          Arguments.of(
                              store,
                              keys[index],
                              store,
                              keys[(index + 1) % keys.length] // second with diff key
                              ));
            });
  }

  @ParameterizedTest(name = "not equals when same store {0} but different keys {1}!={3}")
  @MethodSource("sameStore_differentKey")
  @DisplayName("equals_whenDifferentKey_expectFalse")
  void equals_whenDifferentKey_expectFalse(
      DataStoreType store1, DataStoreKeyType key1, DataStoreType store2, DataStoreKeyType key2) {
    // Arrange
    DataStoreInstanceType a = new DataStoreInstanceType(key1, store1);
    DataStoreInstanceType b = new DataStoreInstanceType(key2, store2);

    // Act & Assert
    assertNotEquals(a, b);
  }

  static Stream<Arguments> sameKey_differentStore() {
    DataStoreType[] stores = DataStoreType.values();
    DataStoreKeyType[] keys = DataStoreKeyType.values();
    return IntStream.range(0, keys.length)
        .boxed()
        .flatMap(
            keyIndex ->
                IntStream.range(0, stores.length)
                    .mapToObj(
                        storeIndex ->
                            Arguments.of(
                                stores[storeIndex],
                                keys[keyIndex],
                                stores[(storeIndex + 1) % stores.length],
                                keys[keyIndex])));
  }

  @ParameterizedTest(name = "not equals when same key {1} but different stores {0}!={2}")
  @MethodSource("sameKey_differentStore")
  @DisplayName("equals_whenDifferentStore_expectFalse")
  void equals_whenDifferentStore_expectFalse(
      DataStoreType store1, DataStoreKeyType key1, DataStoreType store2, DataStoreKeyType key2) {
    // Arrange
    DataStoreInstanceType a = new DataStoreInstanceType(key1, store1);
    DataStoreInstanceType b = new DataStoreInstanceType(key2, store2);

    // Act
    boolean ab = a.equals(b);
    boolean ba = b.equals(a);

    // Assert: inequality is symmetric and fields reflect the scenario
    assertFalse(ab);
    assertFalse(ba);
    assertSame(store1, a.store);
    assertSame(store2, b.store);
    assertNotEquals(store1, store2);
    assertSame(key1, a.key);
    assertSame(key2, b.key);
    assertSame(key1, key2); // same key, different store
  }

  @Test
  @DisplayName("toString_whenCalled_expectDeterministicFormat")
  void toString_whenCalled_expectDeterministicFormat() {
    // Arrange
    DataStoreInstanceType instance =
        new DataStoreInstanceType(DataStoreKeyType.CHK, DataStoreType.STORE);

    // Act
    String s = instance.toString();

    // Assert
    assertEquals("DataStoreInstanceType{store=STORE, key=CHK}", s);
  }
}
