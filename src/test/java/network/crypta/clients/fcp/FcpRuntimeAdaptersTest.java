package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class FcpRuntimeAdaptersTest {

  @Mock private RuntimePorts runtime;

  @Mock private ExecutionPort execution;

  @Mock private RandomnessPort randomness;

  @Test
  void priorityAwareExecutor_whenExecuteCalledWithoutName_usesRunnableClassName() {
    // Arrange
    when(runtime.execution()).thenReturn(execution);
    PriorityAwareExecutor adapter = FcpRuntimeAdapters.priorityAwareExecutor(runtime);
    Runnable job = new TestRunnable();

    // Act
    adapter.execute(job);

    // Assert
    verify(runtime).execution();
    verify(execution).execute(job, TestRunnable.class.getName());
  }

  @ParameterizedTest
  @MethodSource("blankOrNullNames")
  void priorityAwareExecutor_whenJobNameMissing_usesRunnableClassName(String jobName) {
    // Arrange
    when(runtime.execution()).thenReturn(execution);
    PriorityAwareExecutor adapter = FcpRuntimeAdapters.priorityAwareExecutor(runtime);
    Runnable job = new TestRunnable();

    // Act
    adapter.execute(job, jobName);

    // Assert
    verify(execution).execute(job, TestRunnable.class.getName());
  }

  @Test
  void priorityAwareExecutor_whenExecuteCalledWithTickerHint_delegatesProvidedJobName() {
    // Arrange
    when(runtime.execution()).thenReturn(execution);
    PriorityAwareExecutor adapter = FcpRuntimeAdapters.priorityAwareExecutor(runtime);
    Runnable job = new TestRunnable();

    // Act
    adapter.execute(job, "restart-request", true);

    // Assert
    verify(execution).execute(job, "restart-request");
  }

  @Test
  void priorityAwareExecutor_whenIntrospectionRequested_returnsIndependentEmptySnapshots() {
    // Arrange
    when(runtime.execution()).thenReturn(execution);
    PriorityAwareExecutor adapter = FcpRuntimeAdapters.priorityAwareExecutor(runtime);

    // Act
    int[] waitingThreads = adapter.waitingThreads();
    int[] nextWaitingThreads = adapter.waitingThreads();
    int[] runningThreads = adapter.runningThreads();
    int waitingThreadsCount = adapter.getWaitingThreadsCount();

    // Assert
    assertArrayEquals(new int[0], waitingThreads);
    assertArrayEquals(new int[0], runningThreads);
    assertNotSame(waitingThreads, nextWaitingThreads);
    assertEquals(0, waitingThreadsCount);
  }

  @Test
  void priorityAwareExecutor_whenJobIsNull_throwsNullPointerException() {
    // Arrange
    when(runtime.execution()).thenReturn(execution);
    PriorityAwareExecutor adapter = FcpRuntimeAdapters.priorityAwareExecutor(runtime);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> adapter.execute(null, "null-job"));
  }

  @Test
  void secureRandomSource_whenNextBytesCalled_fillsTargetFromRandomnessPort() {
    // Arrange
    byte[] expected = new byte[] {1, 2, 3, 4};
    RandomSource source = FcpRuntimeAdapters.secureRandomSource(randomness);
    byte[] target = new byte[expected.length];
    doAnswer(
            invocation -> {
              byte[] bytes = invocation.getArgument(0);
              System.arraycopy(expected, 0, bytes, 0, expected.length);
              return null;
            })
        .when(randomness)
        .fillSecureRandom(same(target));

    // Act
    source.nextBytes(target);

    // Assert
    assertArrayEquals(expected, target);
    verify(randomness).fillSecureRandom(same(target));
  }

  @Test
  void secureRandomSource_whenPrimitiveRandomMethodsCalled_usesSecureRandomBytes() {
    // Arrange
    RandomSource source = FcpRuntimeAdapters.secureRandomSource(randomness);
    stubSecureRandomResponses(
        randomness, new byte[] {0x12, 0x34, 0x56, 0x78}, new byte[] {(byte) 0x80, 0, 0, 0});

    // Act
    int value = source.nextInt();
    boolean flag = source.nextBoolean();

    // Assert
    assertEquals(0x12345678, value);
    assertTrue(flag);
  }

  @Test
  void secureRandomSource_whenEntropyMethodsAndCloseCalled_returnsZeroWithoutUsingPort() {
    // Arrange
    RandomSource source = FcpRuntimeAdapters.secureRandomSource(randomness);
    EntropySource entropySource = new EntropySource();
    byte[] entropyBytes = new byte[] {9, 8, 7};

    // Act
    int acceptEntropy = source.acceptEntropy(entropySource, 42L, 12);
    int acceptTimerEntropy = source.acceptTimerEntropy(entropySource);
    int acceptTimerEntropyWithBias = source.acceptTimerEntropy(entropySource, 0.5d);
    int acceptEntropyBytes = source.acceptEntropyBytes(entropySource, entropyBytes, 0, 2, 0.25d);

    // Assert
    assertEquals(0, acceptEntropy);
    assertEquals(0, acceptTimerEntropy);
    assertEquals(0, acceptTimerEntropyWithBias);
    assertEquals(0, acceptEntropyBytes);
    assertDoesNotThrow(source::close);
    verifyNoInteractions(randomness);
  }

  @Test
  void secureRandomSource_whenDeserialized_randomCallsFailWithClearMessage() throws Exception {
    // Arrange
    RandomSource original = FcpRuntimeAdapters.secureRandomSource(randomness);
    RandomSource restored = serializeRoundTrip(original);

    // Act + Assert
    NullPointerException exception =
        assertThrows(NullPointerException.class, () -> restored.nextBytes(new byte[1]));
    assertEquals(
        "RandomnessPortRandomSource must not be used after serialization", exception.getMessage());
    assertDoesNotThrow(restored::close);
  }

  @Test
  void nextSecureLong_whenCalled_returnsLongFromSecureBytes() {
    // Arrange
    byte[] expectedBytes = new byte[] {1, 2, 3, 4, 5, 6, 7, 8};
    doAnswer(
            invocation -> {
              byte[] target = invocation.getArgument(0);
              assertEquals(Long.BYTES, target.length);
              System.arraycopy(expectedBytes, 0, target, 0, target.length);
              return null;
            })
        .when(randomness)
        .fillSecureRandom(any(byte[].class));

    // Act
    long value = FcpRuntimeAdapters.nextSecureLong(randomness);

    // Assert
    assertEquals(0x0102030405060708L, value);
  }

  private static Stream<String> blankOrNullNames() {
    return Stream.of(null, "", "   ");
  }

  private static RandomSource serializeRoundTrip(RandomSource source) throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ObjectOutputStream objectOutput = new ObjectOutputStream(output)) {
      objectOutput.writeObject(source);
    }

    try (ObjectInputStream objectInput =
        new ObjectInputStream(new ByteArrayInputStream(output.toByteArray()))) {
      return (RandomSource) objectInput.readObject();
    }
  }

  private static void stubSecureRandomResponses(RandomnessPort randomness, byte[]... responses) {
    AtomicInteger callCount = new AtomicInteger();
    doAnswer(
            invocation -> {
              int index = callCount.getAndIncrement();
              byte[] target = invocation.getArgument(0);
              byte[] response = responses[index];
              assertEquals(response.length, target.length);
              System.arraycopy(response, 0, target, 0, target.length);
              return null;
            })
        .when(randomness)
        .fillSecureRandom(any(byte[].class));
  }

  private static final class TestRunnable implements Runnable {
    @Override
    public void run() {
      // No-op test task used to verify executor delegation.
    }
  }
}
