package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LongTermPushRepullTestTest {

  private static final int BUFFER_SIZE = 4096;

  @Test
  void randomData_whenCalled_expectBucketWithDeterministicBytes() throws Exception {
    int testSize = testSize();
    CountingRandomSource randomSource = new CountingRandomSource();
    InMemoryRandomAccessBucket bucket = new InMemoryRandomAccessBucket();

    Node node = mock(Node.class);
    NodeClientCore clientCore = mock(NodeClientCore.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    when(node.getClientCore()).thenReturn(clientCore);
    when(clientCore.getTempBucketFactory()).thenReturn(tempBucketFactory);
    when(tempBucketFactory.makeBucket(testSize)).thenReturn(bucket);
    when(node.getFastWeakRandom()).thenReturn(randomSource);

    try (RandomAccessBucket result = invokeRandomData(node)) {
      assertNotNull(result);
      assertEquals(testSize, result.size());
      int expectedCalls = (testSize + BUFFER_SIZE - 1) / BUFFER_SIZE;
      assertEquals(expectedCalls, randomSource.getCallCount());

      byte[] data = bucket.data();
      assertEquals(testSize, data.length);
      assertEquals(expectedByte(1, 0), data[0]);
      assertEquals(expectedByte(1, 1), data[1]);
      if (testSize > BUFFER_SIZE) {
        assertEquals(expectedByte(2, 0), data[BUFFER_SIZE]);
      }
      int lastOffset = (testSize - 1) % BUFFER_SIZE;
      assertEquals(expectedByte(expectedCalls, lastOffset), data[testSize - 1]);
    }
  }

  @Test
  void randomData_whenOutputStreamFails_expectIOException() throws Exception {
    int testSize = testSize();

    Node node = mock(Node.class);
    NodeClientCore clientCore = mock(NodeClientCore.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);

    when(node.getClientCore()).thenReturn(clientCore);
    when(clientCore.getTempBucketFactory()).thenReturn(tempBucketFactory);
    when(tempBucketFactory.makeBucket(testSize)).thenReturn(bucket);
    when(bucket.getOutputStream()).thenThrow(new IOException("boom"));

    IOException thrown =
        assertThrows(
            IOException.class,
            () -> {
              try (RandomAccessBucket result = invokeRandomData(node)) {
                assertNotNull(result);
              }
            });
    assertEquals("boom", thrown.getMessage());
  }

  @Test
  void main_whenNoArgs_expectUsageAndExitCode() throws Exception {
    SubprocessResult result = runMainInSubprocess();

    assertEquals(1, result.exitCode());
    assertTrue(
        result.output().contains("Usage: java freenet.node.simulator.LongTermPushPullTest"),
        result::output);
  }

  private static RandomAccessBucket invokeRandomData(Node node) throws Exception {
    Method method = LongTermPushRepullTest.class.getDeclaredMethod("randomData", Node.class);
    method.setAccessible(true);
    try {
      return (RandomAccessBucket) method.invoke(null, node);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof IOException ioException) {
        throw ioException;
      }
      if (cause instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
      if (cause instanceof Error err) {
        throw err;
      }
      throw new IllegalStateException("Unexpected checked exception from randomData()", cause);
    }
  }

  @SuppressWarnings("java:S3011")
  private static int testSize() throws Exception {
    Field field = LongTermPushRepullTest.class.getDeclaredField("TEST_SIZE");
    field.setAccessible(true);
    return (int) field.get(null);
  }

  private static byte expectedByte(int callIndex, int offset) {
    return (byte) (callIndex + offset);
  }

  private static SubprocessResult runMainInSubprocess() throws IOException, InterruptedException {
    List<String> command =
        List.of(
            javaBinaryPath(),
            "-cp",
            System.getProperty("java.class.path"),
            LongTermPushRepullTestTest.MainRunner.class.getName());

    ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
    Process process = pb.start();

    ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
    AtomicReference<Throwable> outputError = new AtomicReference<>();
    Thread outputReader =
        new Thread(
            () -> {
              try (InputStream is = process.getInputStream()) {
                is.transferTo(outputBuffer);
              } catch (IOException e) {
                outputError.set(e);
              }
            },
            "LongTermPushRepullTestTest-MainRunner-output");
    outputReader.setDaemon(true);
    outputReader.start();

    boolean finished = process.waitFor(10, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new IOException("Main subprocess did not exit in time: " + String.join(" ", command));
    }
    outputReader.join(Duration.ofSeconds(2).toMillis());
    if (outputError.get() != null) {
      throw new IOException("Failed reading subprocess output", outputError.get());
    }

    int exitCode = process.exitValue();
    String output = outputBuffer.toString(StandardCharsets.UTF_8);
    return new SubprocessResult(exitCode, output, command);
  }

  private record SubprocessResult(int exitCode, String output, List<String> command) {
    private SubprocessResult {
      command = List.copyOf(command);
    }
  }

  private static String javaBinaryPath() {
    String javaHome = System.getProperty("java.home");
    return Path.of(javaHome, "bin", "java").toString();
  }

  /** Subprocess entrypoint used by {@link #runMainInSubprocess()}. */
  public static final class MainRunner {
    public static void main(String[] args) {
      LongTermPushRepullTest.main(args);
    }
  }

  private static final class CountingRandomSource extends RandomSource {

    private int callCount;

    @Override
    public void nextBytes(byte[] bytes) {
      callCount++;
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = (byte) (callCount + i);
      }
    }

    int getCallCount() {
      return callCount;
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
      // No-op for deterministic test source.
    }
  }

  private static final class InMemoryRandomAccessBucket implements RandomAccessBucket {

    private byte[] data = new byte[0];
    private boolean readOnly;

    @Override
    public OutputStream getOutputStream() throws IOException {
      return newCaptureStream();
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() throws IOException {
      return newCaptureStream();
    }

    @Override
    public InputStream getInputStream() {
      return data.length == 0 ? null : new ByteArrayInputStream(data);
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      return getInputStream();
    }

    @Override
    public String getName() {
      return "InMemoryRandomAccessBucket";
    }

    @Override
    public long size() {
      return data.length;
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }

    @Override
    public void setReadOnly() {
      readOnly = true;
    }

    @Override
    public void free() {
      data = new byte[0];
    }

    @Override
    public RandomAccessBucket createShadow() {
      return null;
    }

    @Override
    public void onResume(ClientContext context) {
      throw new UnsupportedOperationException("resume not supported");
    }

    @Override
    public void storeTo(DataOutputStream dos) {
      throw new UnsupportedOperationException("store not supported");
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException("random access buffer not supported");
    }

    byte[] data() {
      return data.clone();
    }

    private OutputStream newCaptureStream() throws IOException {
      if (readOnly) {
        throw new IOException("Bucket is read-only");
      }
      return new ByteArrayOutputStream() {
        @Override
        public void close() throws IOException {
          super.close();
          data = toByteArray();
        }
      };
    }
  }
}
