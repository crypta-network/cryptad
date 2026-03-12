package network.crypta.node.diagnostics.threads;

import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SuppressWarnings("java:S100")
class NodeThreadInfoTest {

  private static Stream<Arguments> valuesProvider() {
    return Stream.of(
        // typical values
        Arguments.of(1L, 100L, 123_456_789L, "Worker-1", 5, "pool-1", "RUNNABLE"),
        // zeros
        Arguments.of(0L, 0L, 0L, "Main", 10, "main", "TIMED_WAITING"),
        // boundary values (stored as-is)
        Arguments.of(
            Long.MAX_VALUE, Long.MIN_VALUE, Long.MIN_VALUE, "T", Integer.MIN_VALUE, "G", "NEW"));
  }

  @ParameterizedTest
  @MethodSource("valuesProvider")
  @DisplayName("getters_whenConstructedWithValues_expectSameReturns")
  void getters_whenConstructedWithValues_expectSameReturns(
      long id, long jobId, long cpuTime, String name, int prio, String groupName, String state) {
    // Arrange
    NodeThreadInfo info = new NodeThreadInfo(id, jobId, cpuTime, name, prio, groupName, state);

    // Act & Assert
    assertEquals(id, info.getId());
    assertEquals(jobId, info.getJobId());
    assertEquals(cpuTime, info.getCpuTime());
    assertEquals(name, info.getName());
    assertEquals(prio, info.getPrio());
    assertEquals(groupName, info.getGroupName());
    assertEquals(state, info.getState());
  }

  @Test
  @DisplayName("getters_whenNullStringsProvided_expectNullsReturned")
  void getters_whenNullStringsProvided_expectNullsReturned() {
    // Arrange
    NodeThreadInfo info = new NodeThreadInfo(42L, 7L, 11L, null, 3, null, null);

    // Act & Assert
    assertEquals(42L, info.getId());
    assertEquals(7L, info.getJobId());
    assertEquals(11L, info.getCpuTime());
    assertNull(info.getName());
    assertEquals(3, info.getPrio());
    assertNull(info.getGroupName());
    assertNull(info.getState());
  }
}
