package network.crypta.runtime.spi;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.RuntimeMXBean;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class JvmResourceObservationTest {
  @Test
  void capture_whenOptionalCollectorsFail_expectUnavailableRatherThanZero() {
    RuntimeMXBean runtime = mock(RuntimeMXBean.class);
    when(runtime.getStartTime()).thenReturn(123L);
    SecurityException denied = new SecurityException("denied");
    try (var management = mockStatic(ManagementFactory.class)) {
      management.when(ManagementFactory::getRuntimeMXBean).thenReturn(runtime);
      management.when(ManagementFactory::getMemoryMXBean).thenThrow(denied);
      management.when(ManagementFactory::getThreadMXBean).thenThrow(denied);
      management.when(ManagementFactory::getGarbageCollectorMXBeans).thenThrow(denied);

      Map<String, Object> result = JvmResourceObservation.capture();

      assertEquals(123L, result.get("jvmStartEpochMillis"));
      Map<?, ?> metrics = (Map<?, ?>) result.get("metrics");
      assertEquals(9, metrics.size());
      assertTrue(metrics.values().stream().allMatch(java.util.Objects::isNull));
      assertEquals(9, ((List<?>) result.get("unavailable")).size());
    }
  }

  @Test
  void capture_whenIdentityReadFails_expectFailureInsteadOfUsableSnapshot() {
    SecurityException denied = new SecurityException("denied");
    try (var management = mockStatic(ManagementFactory.class)) {
      management.when(ManagementFactory::getRuntimeMXBean).thenThrow(denied);

      SecurityException actual =
          assertThrows(SecurityException.class, JvmResourceObservation::capture);

      assertSame(denied, actual);
    }
  }

  @Test
  void capture_whenGcStatisticsUnsupportedOrOverflow_expectBothTotalsUnavailable() {
    for (long secondCount : new long[] {-1L, 1L}) {
      RuntimeMXBean runtime = mock(RuntimeMXBean.class);
      GarbageCollectorMXBean first = mock(GarbageCollectorMXBean.class);
      GarbageCollectorMXBean second = mock(GarbageCollectorMXBean.class);
      when(first.getCollectionCount()).thenReturn(Long.MAX_VALUE);
      when(first.getCollectionTime()).thenReturn(10L);
      when(second.getCollectionCount()).thenReturn(secondCount);
      when(second.getCollectionTime()).thenReturn(20L);
      try (var management = mockStatic(ManagementFactory.class)) {
        management.when(ManagementFactory::getRuntimeMXBean).thenReturn(runtime);
        management
            .when(ManagementFactory::getGarbageCollectorMXBeans)
            .thenReturn(List.of(first, second));

        Map<String, Object> result = JvmResourceObservation.capture();

        Map<?, ?> metrics = (Map<?, ?>) result.get("metrics");
        assertNull(metrics.get("gcCount"));
        assertNull(metrics.get("gcTimeMillis"));
      }
    }
  }

  @Test
  void capture_whenMaximaAreUndefinedAndCollectorNameIsUnsafe_expectExplicitNulls() {
    RuntimeMXBean runtime = mock(RuntimeMXBean.class);
    MemoryMXBean memory = mock(MemoryMXBean.class);
    GarbageCollectorMXBean collector = mock(GarbageCollectorMXBean.class);
    MemoryUsage usage = new MemoryUsage(-1, 2, 3, -1);
    when(memory.getHeapMemoryUsage()).thenReturn(usage);
    when(memory.getNonHeapMemoryUsage()).thenReturn(usage);
    when(collector.getName()).thenReturn("unsafe\nname");
    when(collector.getCollectionCount()).thenReturn(2L);
    when(collector.getCollectionTime()).thenReturn(3L);
    try (var management = mockStatic(ManagementFactory.class)) {
      management.when(ManagementFactory::getRuntimeMXBean).thenReturn(runtime);
      management.when(ManagementFactory::getMemoryMXBean).thenReturn(memory);
      management.when(ManagementFactory::getGarbageCollectorMXBeans).thenReturn(List.of(collector));

      Map<String, Object> result = JvmResourceObservation.capture();

      Map<?, ?> metrics = (Map<?, ?>) result.get("metrics");
      Map<?, ?> configuration = (Map<?, ?>) result.get("configuration");
      assertNull(metrics.get("heapMaxBytes"));
      assertNull(metrics.get("nonHeapMaxBytes"));
      assertNull(configuration.get("heapInitialBytes"));
      assertNull(configuration.get("garbageCollectors"));
      assertEquals(2L, metrics.get("gcCount"));
      assertEquals(3L, metrics.get("gcTimeMillis"));
    }
  }
}
