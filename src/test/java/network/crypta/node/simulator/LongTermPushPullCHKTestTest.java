package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStarter.TestNodeParameters;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LongTermPushPullCHKTestTest {

  @Test
  void buildNodeParameters_whenCalledWithValues_expectParametersConfigured(@TempDir Path tempDir)
      throws ReflectiveOperationException {
    // Arrange
    int darknetPort = 9010;
    int opennetPort = 9011;
    File baseDirectory = tempDir.resolve("base").toFile();
    RandomSource random = new PatternRandomSource();
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    int storeSize = 42;

    // Act
    TestNodeParameters params =
        invokeBuildNodeParameters(
            darknetPort, opennetPort, baseDirectory, random, executor, storeSize, false);

    // Assert
    assertEquals(darknetPort, params.getPort());
    assertEquals(opennetPort, params.getOpennetPort());
    assertSame(baseDirectory, params.getBaseDirectory());
    assertEquals(Node.DEFAULT_MAX_HTL, params.getMaxHTL());
    assertSame(random, params.getRandom());
    assertSame(executor, params.getExecutor());
    assertEquals(1000, params.getThreadLimit());
    assertEquals(storeSize, params.getStoreSize());
    assertTrue(params.isRamStore());
    assertTrue(params.isEnableSwapping());
    assertTrue(params.isEnableARKs());
    assertTrue(params.isEnableULPRs());
    assertTrue(params.isEnablePerNodeFailureTables());
    assertTrue(params.isEnableSwapQueueing());
    assertTrue(params.isEnablePacketCoalescing());
    assertEquals(12 * 1024, params.getOutputBandwidthLimit());
    assertFalse(params.isEnableFOAF());
    assertTrue(params.isConnectToSeednodes());
  }

  @Test
  void buildNodeParameters_whenFlagsEnabled_expectFlagsSet(@TempDir Path tempDir)
      throws ReflectiveOperationException {
    // Arrange
    File baseDirectory = tempDir.resolve("base-enabled").toFile();
    RandomSource random = new PatternRandomSource();
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);

    // Act
    TestNodeParameters params =
        invokeBuildNodeParameters(7010, 7011, baseDirectory, random, executor, 128, true);

    // Assert
    assertTrue(params.isEnableFOAF());
    assertTrue(params.isConnectToSeednodes());
  }

  @Test
  void getHistoricURI_whenFileMissing_expectIOException() throws IOException {
    // Arrange
    String uid = "LongTermPushPullCHKTestTest-missing";
    Path path = Path.of(uid + ".csv");
    Files.deleteIfExists(path);
    Calendar targetDate = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
    targetDate.set(2025, Calendar.JANUARY, 5, 0, 0, 0);

    // Act + Assert
    int lookupIndex = 1;
    assertThrows(IOException.class, () -> invokeGetHistoricURI(uid, lookupIndex, targetDate));
    assertFalse(Files.exists(path));
  }

  @Test
  void getHistoricURI_whenMatchingLinePresent_expectNullDueToLengthCheck()
      throws IOException, ReflectiveOperationException {
    // Arrange
    String uid = "LongTermPushPullCHKTestTest-sample";
    Path path = Path.of(uid + ".csv");
    Calendar targetDate = new GregorianCalendar(TimeZone.getTimeZone("GMT"));
    targetDate.set(2024, Calendar.MARCH, 14, 0, 0, 0);

    String date = LongTermTest.dateFormat.format(targetDate.getTime());
    String uri = FreenetURI.EMPTY_CHK_URI.toASCIIString();

    String line = String.join("!", date, "1", "100", "12", uri, "15", uri);
    try (FileOutputStream outputStream = new FileOutputStream(path.toFile())) {
      outputStream.write(line.getBytes(StandardCharsets.UTF_8));
      outputStream.write('\n');
    }

    // Act
    int lookupIndex = 1;
    FreenetURI result = invokeGetHistoricURI(uid, lookupIndex, targetDate);
    FreenetURI alternateResult = invokeGetHistoricURI(uid, 2, targetDate);

    // Assert
    assertNull(result);
    assertNull(alternateResult);

    // Cleanup
    Files.delete(path);
  }

  @Test
  @SuppressWarnings({"resource"})
  void randomData_whenCalled_writesExpectedSizeAndPattern()
      throws IOException, ReflectiveOperationException {
    // Arrange
    int testSize = readTestSize();
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try (RandomAccessBucket bucket = mock(RandomAccessBucket.class)) {
      when(bucket.getOutputStream()).thenReturn(output);

      TempBucketFactory bucketFactory = mock(TempBucketFactory.class);
      when(bucketFactory.makeBucket(testSize)).thenReturn(bucket);

      NodeClientCore clientCore = mock(NodeClientCore.class);
      when(clientCore.getTempBucketFactory()).thenReturn(bucketFactory);

      Node node = mock(Node.class);
      when(node.getClientCore()).thenReturn(clientCore);
      when(node.getFastWeakRandom()).thenReturn(new PatternRandomSource());

      // Act
      try (RandomAccessBucket result = invokeRandomData(node)) {
        // Assert
        assertSame(bucket, result);
        verify(bucketFactory).makeBucket(testSize);
        assertEquals(testSize, output.size());
        byte[] bytes = output.toByteArray();
        assertNotNull(bytes);
        assertEquals(0, bytes[0]);
        assertEquals(1, bytes[1]);
        assertEquals((byte) 255, bytes[255]);
        assertEquals((byte) 0, bytes[256]);
        assertEquals((byte) ((testSize - 1) & 0xFF), bytes[testSize - 1]);
      }
    }
  }

  @SuppressWarnings("java:S3011")
  private static TestNodeParameters invokeBuildNodeParameters(
      int darknetPort,
      int opennetPort,
      File baseDirectory,
      RandomSource random,
      PriorityAwareExecutor executor,
      int storeSize,
      boolean enableFoaf)
      throws ReflectiveOperationException {
    Method method =
        LongTermPushPullCHKTest.class.getDeclaredMethod(
            "buildNodeParameters",
            int.class,
            int.class,
            File.class,
            RandomSource.class,
            PriorityAwareExecutor.class,
            int.class,
            boolean.class);
    method.setAccessible(true);
    return (TestNodeParameters)
        method.invoke(
            null, darknetPort, opennetPort, baseDirectory, random, executor, storeSize, enableFoaf);
  }

  @SuppressWarnings("java:S3011")
  private static FreenetURI invokeGetHistoricURI(String uid, int i, Calendar targetDate)
      throws IOException, ReflectiveOperationException {
    Method method =
        LongTermPushPullCHKTest.class.getDeclaredMethod(
            "getHistoricURI", String.class, int.class, Calendar.class);
    method.setAccessible(true);
    try {
      return (FreenetURI) method.invoke(null, uid, i, targetDate);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof IOException io) {
        throw io;
      }
      if (cause instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
      if (cause instanceof Error error) {
        throw error;
      }
      throw new IllegalStateException("Unexpected exception while invoking getHistoricURI", cause);
    }
  }

  @SuppressWarnings("java:S3011")
  private static RandomAccessBucket invokeRandomData(Node node)
      throws IOException, ReflectiveOperationException {
    Method method = LongTermPushPullCHKTest.class.getDeclaredMethod("randomData", Node.class);
    method.setAccessible(true);
    try {
      return (RandomAccessBucket) method.invoke(null, node);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof IOException io) {
        throw io;
      }
      if (cause instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
      if (cause instanceof Error error) {
        throw error;
      }
      throw new IllegalStateException("Unexpected exception while invoking randomData", cause);
    }
  }

  @SuppressWarnings("java:S3011")
  private static int readTestSize() throws ReflectiveOperationException {
    Field field = LongTermPushPullCHKTest.class.getDeclaredField("TEST_SIZE");
    field.setAccessible(true);
    return field.getInt(null);
  }

  private static final class PatternRandomSource extends RandomSource {
    private int counter;

    @Override
    public void nextBytes(byte[] bytes) {
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) (counter & 0xFF);
        counter++;
      }
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // No resources to release for the deterministic test random source.
    }
  }
}
