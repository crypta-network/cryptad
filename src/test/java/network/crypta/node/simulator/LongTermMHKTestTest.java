package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import network.crypta.crypt.RandomSource;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.TempBucketFactory;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LongTermMHKTestTest {

  @ParameterizedTest
  @MethodSource("invalidArgs")
  void main_whenArgsInvalid_expectExitCode1(String[] args) throws Exception {
    Process process = null;
    try {
      process = startMainProcess(args);
      assertTrue(process.waitFor(10, TimeUnit.SECONDS));
      String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      assertEquals(1, process.exitValue());
      assertTrue(output.contains("Usage:"));
    } finally {
      if (process != null && process.isAlive()) {
        process.destroyForcibly();
      }
    }
  }

  @Test
  void randomData_whenBucketCreated_writesExactSizeAndClosesStream() throws Exception {
    int testSize = readTestSize();
    TrackingOutputStream outputStream = new TrackingOutputStream(false);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    RandomSource randomSource = mock(RandomSource.class);
    Node node = prepareNodeForBucket(bucket, outputStream, testSize, randomSource);

    try (RandomAccessBucket result = invokeRandomData(node)) {
      assertEquals(bucket, result);
      assertEquals(testSize, outputStream.size());
      assertTrue(outputStream.isClosed());
      verify(randomSource, atLeastOnce()).nextBytes(any(byte[].class));
    }
  }

  @Test
  void randomData_whenWriteFails_throwsIOExceptionAndClosesStream() throws Exception {
    int testSize = readTestSize();
    TrackingOutputStream outputStream = new TrackingOutputStream(true);
    RandomAccessBucket bucket = mock(RandomAccessBucket.class);
    RandomSource randomSource = mock(RandomSource.class);
    Node node = prepareNodeForBucket(bucket, outputStream, testSize, randomSource);

    try {
      RandomAccessBucket result = invokeRandomData(node);
      try (result) {
        fail("Expected randomData to throw");
      }
    } catch (InvocationTargetException thrown) {
      assertNotNull(thrown.getCause());
      assertInstanceOf(IOException.class, thrown.getCause());
      assertTrue(outputStream.isClosed());
    }
  }

  private static Stream<Arguments> invalidArgs() {
    return Stream.of(
        Arguments.of((Object) new String[] {}),
        Arguments.of((Object) new String[] {"a", "b", "c"}));
  }

  private static Process startMainProcess(String[] args) throws IOException {
    String javaExecutable = javaExecutable();
    String classpath = System.getProperty("java.class.path");
    ProcessBuilder builder = new ProcessBuilder();
    builder.command(buildCommand(javaExecutable, classpath, args));
    builder.redirectErrorStream(true);
    return builder.start();
  }

  private static String javaExecutable() {
    String javaHome = System.getProperty("java.home");
    String executable = isWindows() ? "java.exe" : "java";
    return Path.of(javaHome, "bin", executable).toString();
  }

  private static boolean isWindows() {
    return System.getProperty("os.name").toLowerCase(Locale.US).contains("win");
  }

  private static String[] buildCommand(String javaExecutable, String classpath, String[] args) {
    String[] command = new String[4 + args.length];
    command[0] = javaExecutable;
    command[1] = "-cp";
    command[2] = classpath;
    command[3] = "network.crypta.node.simulator.LongTermMHKTest";
    System.arraycopy(args, 0, command, 4, args.length);
    return command;
  }

  private static Node prepareNodeForBucket(
      RandomAccessBucket bucket, OutputStream outputStream, int testSize, RandomSource randomSource)
      throws IOException {
    Node node = mock(Node.class);
    NodeClientCore clientCore = mock(NodeClientCore.class);
    TempBucketFactory tempBucketFactory = mock(TempBucketFactory.class);

    when(node.getClientCore()).thenReturn(clientCore);
    when(clientCore.getTempBucketFactory()).thenReturn(tempBucketFactory);
    when(tempBucketFactory.makeBucket((long) testSize)).thenReturn(bucket);
    when(bucket.getOutputStream()).thenReturn(outputStream);
    when(node.getFastWeakRandom()).thenReturn(randomSource);

    return node;
  }

  private static int readTestSize() throws Exception {
    Field field = LongTermMHKTest.class.getDeclaredField("TEST_SIZE");
    field.setAccessible(true);
    return field.getInt(null);
  }

  private static RandomAccessBucket invokeRandomData(Node node) throws Exception {
    Method method = LongTermMHKTest.class.getDeclaredMethod("randomData", Node.class);
    method.setAccessible(true);
    return (RandomAccessBucket) method.invoke(null, node);
  }

  private static final class TrackingOutputStream extends OutputStream {
    private final ByteArrayOutputStream delegate = new ByteArrayOutputStream();
    private final boolean failOnWrite;
    private boolean closed;

    private TrackingOutputStream(boolean failOnWrite) {
      this.failOnWrite = failOnWrite;
    }

    @Override
    public void write(int b) throws IOException {
      if (failOnWrite) {
        throw new IOException("forced write failure");
      }
      delegate.write(b);
    }

    @Override
    public void write(byte @NonNull [] b, int off, int len) throws IOException {
      if (failOnWrite) {
        throw new IOException("forced write failure");
      }
      delegate.write(b, off, len);
    }

    @Override
    public void close() {
      closed = true;
    }

    private int size() {
      return delegate.size();
    }

    private boolean isClosed() {
      return closed;
    }
  }
}
