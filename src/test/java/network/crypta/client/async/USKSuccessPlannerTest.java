package network.crypta.client.async;

import java.util.List;
import java.util.stream.Stream;
import network.crypta.keys.ClientSSKBlock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class USKSuccessPlannerTest {

  @Test
  void createSuccessPlan_whenCalled_populatesFields() {
    // Arrange
    USKSuccessPlanner planner = new USKSuccessPlanner();
    List<USKAttempt> killAttempts = List.of(org.mockito.Mockito.mock(USKAttempt.class));

    // Act
    USKSuccessPlanner.SuccessPlan plan = planner.createSuccessPlan(true, 7L, false, killAttempts);

    // Assert
    assertEquals(true, plan.decode);
    assertEquals(7L, plan.curLatest);
    assertEquals(false, plan.registerNow);
    assertSame(killAttempts, plan.killAttempts);
  }

  @Test
  void createFoundPlan_whenCalled_populatesFields() {
    // Arrange
    USKSuccessPlanner planner = new USKSuccessPlanner();
    List<USKAttempt> killAttempts = List.of(org.mockito.Mockito.mock(USKAttempt.class));

    // Act
    USKSuccessPlanner.FoundPlan plan = planner.createFoundPlan(false, true, killAttempts);

    // Assert
    assertEquals(false, plan.decode);
    assertEquals(true, plan.registerNow);
    assertSame(killAttempts, plan.killAttempts);
  }

  @ParameterizedTest
  @MethodSource("decodeCases")
  void shouldDecode_whenEvaluated_returnsExpectedDecision(
      long curLatest, long lastEd, boolean dontUpdate, boolean blockPresent, boolean expected) {
    // Arrange
    ClientSSKBlock block = blockPresent ? org.mockito.Mockito.mock(ClientSSKBlock.class) : null;

    // Act
    boolean decision = USKSuccessPlanner.shouldDecode(curLatest, lastEd, dontUpdate, block);

    // Assert
    assertEquals(expected, decision);
  }

  private static Stream<Arguments> decodeCases() {
    return Stream.of(
        Arguments.of(5L, 7L, false, true, false),
        Arguments.of(7L, 7L, false, false, true),
        Arguments.of(9L, 7L, false, true, true),
        Arguments.of(9L, 7L, true, true, true),
        Arguments.of(9L, 7L, true, false, false));
  }
}
