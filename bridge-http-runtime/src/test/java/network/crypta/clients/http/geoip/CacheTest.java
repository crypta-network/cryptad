package network.crypta.clients.http.geoip;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/** Unit tests for {@link Cache}. */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test naming: method_whenCondition_expectOutcome
class CacheTest {

  @ParameterizedTest(name = "{index}: {2}")
  @MethodSource("constructorCases")
  @DisplayName("getCodes()/getIps() return the exact arrays provided to the constructor")
  void constructor_whenAnyArraysProvided_gettersReturnSameReferences(
      short[] codes, int[] ips, String description) {
    // Arrange

    // Act
    Cache cache = new Cache(codes, ips);

    // Assert
    assertSame(
        codes,
        cache.getCodes(),
        () -> "Expected getCodes() to return the same reference (" + description + ")");
    assertSame(
        ips,
        cache.getIps(),
        () -> "Expected getIps() to return the same reference (" + description + ")");
  }

  private static Stream<Arguments> constructorCases() {
    return Stream.of(
        Arguments.of(new short[] {1, 2, 3}, new int[] {0x01020304, 0x0a000001}, "non-null arrays"),
        Arguments.of(null, new int[] {1}, "null codes array"),
        Arguments.of(new short[] {1}, null, "null ips array"),
        Arguments.of(null, null, "both arrays null"),
        Arguments.of(new short[0], new int[0], "empty arrays"));
  }

  @Test
  @DisplayName("Mutating the codes array is visible through getCodes() (live backing array)")
  void getCodes_whenBackingArrayMutated_reflectsMutation() {
    // Arrange
    short[] codes = new short[] {10};
    Cache cache = new Cache(codes, new int[] {123});

    // Act
    codes[0] = 42;

    // Assert
    assertEquals((short) 42, cache.getCodes()[0]);
  }

  @Test
  @DisplayName("Mutating the ips array is visible through getIps() (live backing array)")
  void getIps_whenBackingArrayMutated_reflectsMutation() {
    // Arrange
    int[] ips = new int[] {123};
    Cache cache = new Cache(new short[] {10}, ips);

    // Act
    ips[0] = 456;

    // Assert
    assertEquals(456, cache.getIps()[0]);
  }
}
