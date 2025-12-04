package org.sevenzip.compression.lzma;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BaseTest {

  @Nested
  class StateUpdateChar {
    static Stream<Arguments> cases() {
      return Stream.of(
          arguments(0, 0),
          arguments(3, 0),
          arguments(4, 1),
          arguments(9, 6),
          arguments(10, 4),
          arguments(11, 5));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void stateUpdateChar_variousIndices_returnsExpectedState(int index, int expected) {
      // Act
      int result = Base.stateUpdateChar(index);

      // Assert
      assertEquals(expected, result);
    }
  }

  @Nested
  class StateUpdateMatch {
    static Stream<Arguments> cases() {
      return Stream.of(arguments(0, 7), arguments(6, 7), arguments(7, 10), arguments(11, 10));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void stateUpdateMatch_variousIndices_returnsExpectedState(int index, int expected) {
      int result = Base.stateUpdateMatch(index);
      assertEquals(expected, result);
    }
  }

  @Nested
  class StateUpdateRep {
    static Stream<Arguments> cases() {
      return Stream.of(arguments(0, 8), arguments(6, 8), arguments(7, 11), arguments(11, 11));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void stateUpdateRep_variousIndices_returnsExpectedState(int index, int expected) {
      int result = Base.stateUpdateRep(index);
      assertEquals(expected, result);
    }
  }

  @Nested
  class StateUpdateShortRep {
    static Stream<Arguments> cases() {
      return Stream.of(arguments(0, 9), arguments(6, 9), arguments(7, 11), arguments(11, 11));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void stateUpdateShortRep_variousIndices_returnsExpectedState(int index, int expected) {
      int result = Base.stateUpdateShortRep(index);
      assertEquals(expected, result);
    }
  }

  @Nested
  class IsCharState {
    static Stream<Arguments> cases() {
      return Stream.of(
          arguments(0, true), arguments(6, true), arguments(7, false), arguments(11, false));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void isCharState_boundariesReflectLiteralVsMatchStates(int index, boolean expected) {
      boolean result = Base.isCharState(index);
      if (expected) {
        assertTrue(result);
      } else {
        assertFalse(result);
      }
    }
  }

  @Nested
  class GetLenToPosState {

    static Stream<Arguments> cases() {
      return Stream.of(
          arguments(Base.MATCH_MIN_LEN, 0),
          arguments(Base.MATCH_MIN_LEN + 1, 1),
          arguments(Base.MATCH_MIN_LEN + Base.NUM_LEN_TO_POS_STATES - 1, 3),
          arguments(
              Base.MATCH_MIN_LEN + Base.NUM_LEN_TO_POS_STATES, Base.NUM_LEN_TO_POS_STATES - 1),
          arguments(Base.MATCH_MIN_LEN + 20, Base.NUM_LEN_TO_POS_STATES - 1));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void getLenToPosState_variousLengths_clampsAtMaxBucket(int length, int expected) {
      int result = Base.getLenToPosState(length);
      assertEquals(expected, result);
    }

    @Test
    void getLenToPosState_whenLengthAtMinimum_returnsZero() {
      int result = Base.getLenToPosState(Base.MATCH_MIN_LEN);
      assertEquals(0, result);
    }
  }
}
