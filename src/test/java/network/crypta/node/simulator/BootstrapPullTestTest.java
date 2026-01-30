package network.crypta.node.simulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.keys.FreenetURI;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;

@SuppressWarnings("java:S100")
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(Resources.SYSTEM_OUT)
@ResourceLock(Resources.SYSTEM_ERR)
@ResourceLock("port:9481")
class BootstrapPullTestTest {

  private static final int FCP_PORT = 9481;
  private static final String OUTPUT_PREFIX = "Output:\n";
  private static final String DEFAULT_CHK_URI = "CHK@";

  @TempDir Path tempDir;

  private final int originalTestSize = BootstrapPullTest.getTestSize();

  @AfterEach
  void tearDown() {
    setTestSize(originalTestSize);
  }

  @Test
  void insertData_whenPutSuccessful_expectReturnsUriAndSendsExactBytes() throws Exception {
    int testSize = 128;
    setTestSize(testSize);
    byte[] data = deterministicBytes(testSize);
    File dataFile = writeTempFile("insert-success", data);

    try (FcpServer server = FcpServer.putSuccessful(data)) {
      FreenetURI uri =
          assertTimeoutPreemptively(
              Duration.ofSeconds(5), () -> BootstrapPullTestInvoker.insertData(dataFile));

      assertNotNull(uri);
      assertEquals(DEFAULT_CHK_URI, uri.toString());
      server.assertNoServerError();
    }
  }

  @Test
  void insertData_whenPutProgressThenPutSuccessful_expectContinuesLoopUntilSuccess()
      throws Exception {
    int testSize = 64;
    setTestSize(testSize);
    byte[] data = deterministicBytes(testSize);
    File dataFile = writeTempFile("insert-progress", data);

    try (FcpServer server = FcpServer.putProgressThenSuccessful(data)) {
      FreenetURI uri =
          assertTimeoutPreemptively(
              Duration.ofSeconds(5), () -> BootstrapPullTestInvoker.insertData(dataFile));

      assertNotNull(uri);
      assertEquals(DEFAULT_CHK_URI, uri.toString());
      server.assertNoServerError();
    }
  }

  @Test
  void insertData_whenServerDoesNotSendNodeHello_expectSystemExitInsisterProblem()
      throws Exception {
    int testSize = 16;
    setTestSize(testSize);
    byte[] data = deterministicBytes(testSize);
    File dataFile = writeTempFile("no-nodehello", data);

    try (var _ = FcpServer.notNodeHello()) {
      SubprocessResult result = runInsertDataInSubprocess(dataFile, testSize);
      assertEquals(
          expectedOsExitCode(BootstrapPullTest.EXIT_INSERTER_PROBLEM),
          result.exitCode(),
          () -> OUTPUT_PREFIX + result.output());
    }
  }

  @Test
  void insertData_whenPutFailed_expectSystemExitInsertFailed() throws Exception {
    int testSize = 32;
    setTestSize(testSize);
    byte[] data = deterministicBytes(testSize);
    File dataFile = writeTempFile("put-failed", data);

    try (var _ = FcpServer.putFailed(data)) {
      SubprocessResult result = runInsertDataInSubprocess(dataFile, testSize);
      assertEquals(
          expectedOsExitCode(BootstrapPullTest.EXIT_INSERT_FAILED),
          result.exitCode(),
          () -> OUTPUT_PREFIX + result.output());
    }
  }

  @Test
  void insertData_whenProtocolError_expectSystemExitInserterProblem() throws Exception {
    int testSize = 32;
    setTestSize(testSize);
    byte[] data = deterministicBytes(testSize);
    File dataFile = writeTempFile("protocol-error", data);

    try (var _ = FcpServer.protocolErrorAfterData(data)) {
      SubprocessResult result = runInsertDataInSubprocess(dataFile, testSize);
      assertEquals(
          expectedOsExitCode(BootstrapPullTest.EXIT_INSERTER_PROBLEM),
          result.exitCode(),
          () -> OUTPUT_PREFIX + result.output());
    }
  }

  private static int expectedOsExitCode(int javaExitCode) {
    // POSIX process exit codes are 8-bit; System.exit(>255) wraps.
    return javaExitCode & 0xFF;
  }

  private static synchronized void setTestSize(int testSize) {
    BootstrapPullTest.setTestSize(testSize);
  }

  private static byte[] deterministicBytes(int size) {
    byte[] data = new byte[size];
    for (int i = 0; i < size; i++) {
      data[i] = (byte) ((i * 31) ^ (i >>> 1));
    }
    return data;
  }

  private File writeTempFile(String prefix, byte[] data) throws IOException {
    Path file = Files.createTempFile(tempDir, prefix, ".bin");
    Files.write(file, data);
    return file.toFile();
  }

  private static final class BootstrapPullTestInvoker {
    @SuppressWarnings("java:S3011")
    private static FreenetURI insertData(File dataFile)
        throws IOException, ReflectiveOperationException {
      Method method = BootstrapPullTest.class.getDeclaredMethod("insertData", File.class);
      method.setAccessible(true);
      try {
        return (FreenetURI) method.invoke(null, dataFile);
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
        throw new IllegalStateException("Unexpected checked exception from insertData()", cause);
      }
    }
  }

  private static SubprocessResult runInsertDataInSubprocess(File dataFile, int testSize)
      throws IOException, InterruptedException {
    List<String> command = new ArrayList<>();
    command.add(javaBinaryPath());
    command.add("-cp");
    command.add(System.getProperty("java.class.path"));
    command.add(BootstrapPullTestTest.InsertDataRunner.class.getName());
    command.add(Integer.toString(testSize));
    command.add(dataFile.getAbsolutePath());

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
            "BootstrapPullTestTest-InsertDataRunner-output");
    outputReader.setDaemon(true);
    outputReader.start();

    boolean finished = process.waitFor(10, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new IOException(
          "InsertData subprocess did not exit in time: " + String.join(" ", command));
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

    @Override
    public @NonNull String toString() {
      return "exitCode="
          + exitCode
          + "\nCommand: "
          + String.join(" ", command)
          + "\nOutput:\n"
          + output;
    }
  }

  private static String javaBinaryPath() {
    String javaHome = System.getProperty("java.home");
    return Path.of(javaHome, "bin", "java").toString();
  }

  /**
   * Subprocess entrypoint used by {@link #runInsertDataInSubprocess(File, int)}.
   *
   * <p>This is required because {@link System#exit(int)} cannot be intercepted in-process on this
   * runtime (Security Manager is disabled).
   */
  public static final class InsertDataRunner {
    public static void main(String[] args) throws IOException, ReflectiveOperationException {
      if (args.length != 2) {
        throw new IllegalArgumentException("Expected args: <testSize> <dataFile>");
      }
      int testSize = Integer.parseInt(args[0]);
      File dataFile = new File(args[1]);

      BootstrapPullTest.setTestSize(testSize);
      BootstrapPullTestInvoker.insertData(dataFile);
    }
  }

  private static final class FcpServer implements AutoCloseable {

    private final ServerSocket serverSocket;
    private final Thread serverThread;
    private final CountDownLatch done;
    private final AtomicReference<Throwable> serverError;

    private FcpServer(
        ServerSocket serverSocket,
        Thread serverThread,
        CountDownLatch done,
        AtomicReference<Throwable> serverError) {
      this.serverSocket = serverSocket;
      this.serverThread = serverThread;
      this.done = done;
      this.serverError = serverError;
    }

    static FcpServer putSuccessful(byte[] expectedData) throws IOException {
      return start(
          in -> {
            FcpConversation conversation = FcpConversation.start(in);
            conversation.readClientHello();
            conversation.sendNodeHello();
            conversation.readClientPutAndData(expectedData);
            conversation.send("PutSuccessful", Map.of("URI", DEFAULT_CHK_URI));
          });
    }

    static FcpServer putProgressThenSuccessful(byte[] expectedData) throws IOException {
      return start(
          in -> {
            FcpConversation conversation = FcpConversation.start(in);
            conversation.readClientHello();
            conversation.sendNodeHello();
            conversation.readClientPutAndData(expectedData);
            conversation.send("PutProgress", Map.of("Succeeded", "0"));
            conversation.send("PutSuccessful", Map.of("URI", DEFAULT_CHK_URI));
          });
    }

    static FcpServer putFailed(byte[] expectedData) throws IOException {
      return start(
          in -> {
            FcpConversation conversation = FcpConversation.start(in);
            conversation.readClientHello();
            conversation.sendNodeHello();
            conversation.readClientPutAndData(expectedData);
            conversation.send("PutFailed", Map.of("Code", "1"));
          });
    }

    static FcpServer protocolErrorAfterData(byte[] expectedData) throws IOException {
      return start(
          in -> {
            FcpConversation conversation = FcpConversation.start(in);
            conversation.readClientHello();
            conversation.sendNodeHello();
            conversation.readClientPutAndData(expectedData);
            conversation.send("ProtocolError", Map.of("Code", "1"));
          });
    }

    static FcpServer notNodeHello() throws IOException {
      return start(
          in -> {
            FcpConversation conversation = FcpConversation.start(in);
            conversation.readClientHello();
            conversation.send("NotNodeHello", Map.of());
          });
    }

    private static FcpServer start(ServerInteraction interaction) throws IOException {
      ServerSocket serverSocket = bindLocalhost();
      AtomicReference<Throwable> serverError = new AtomicReference<>();
      CountDownLatch done = new CountDownLatch(1);
      Thread thread = createServerThread(serverSocket, interaction, serverError, done);
      return startServer(serverSocket, thread, done, serverError);
    }

    private static ServerSocket bindLocalhost() throws IOException {
      InetAddress localhost = InetAddress.getAllByName("127.0.0.1")[0];
      ServerSocket serverSocket = new ServerSocket();
      serverSocket.setReuseAddress(true);
      try {
        serverSocket.bind(new InetSocketAddress(localhost, FCP_PORT), 1);
      } catch (IOException e) {
        assumeTrue(
            false,
            "Port "
                + FCP_PORT
                + " is already in use; skipping BootstrapPullTest.insertData tests.");
        throw e;
      }
      return serverSocket;
    }

    private static Thread createServerThread(
        ServerSocket serverSocket,
        ServerInteraction interaction,
        AtomicReference<Throwable> serverError,
        CountDownLatch done) {
      Thread thread =
          new Thread(
              () -> {
                try (Socket socket = serverSocket.accept()) {
                  socket.setSoTimeout((int) Duration.ofSeconds(5).toMillis());
                  interaction.run(socket);
                } catch (Exception | AssertionError e) {
                  serverError.set(e);
                } finally {
                  done.countDown();
                }
              },
              "BootstrapPullTestTest-FcpServer");
      thread.setDaemon(true);
      return thread;
    }

    private static FcpServer startServer(
        ServerSocket serverSocket,
        Thread thread,
        CountDownLatch done,
        AtomicReference<Throwable> serverError) {
      FcpServer server = new FcpServer(serverSocket, thread, done, serverError);
      server.serverThread.start();
      return server;
    }

    void assertNoServerError() throws IOException {
      awaitDone();
      Throwable error = serverError.get();
      if (error == null) {
        return;
      }
      throw new AssertionError("FCP server thread failed", error);
    }

    private void awaitDone() throws IOException {
      try {
        if (!done.await(5, TimeUnit.SECONDS)) {
          throw new IOException("Server did not finish in time");
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted while waiting for server", e);
      }
    }

    @Override
    public void close() throws Exception {
      try {
        serverSocket.close();
      } finally {
        assertNoServerError();
      }
    }
  }

  @FunctionalInterface
  private interface ServerInteraction {
    void run(Socket socket) throws IOException;
  }

  private static final class FcpConversation {
    private final InputStream input;
    private final OutputStream output;

    private FcpConversation(InputStream input, OutputStream output) {
      this.input = input;
      this.output = output;
    }

    static FcpConversation start(Socket socket) throws IOException {
      return new FcpConversation(socket.getInputStream(), socket.getOutputStream());
    }

    void readClientHello() throws IOException {
      String name = readLine(input);
      assertEquals("ClientHello", name);
      Map<String, String> fields = readFieldsUntilEnd(input);
      assertEquals("0.7", fields.get("ExpectedVersion"));
      assertNotNull(fields.get("Name"));
    }

    void sendNodeHello() throws IOException {
      send("NodeHello", Map.of());
    }

    void readClientPutAndData(byte[] expectedData) throws IOException {
      String name = readLine(input);
      assertEquals("ClientPut", name);

      Map<String, String> fields = readFieldsUntilData(input);
      assertEquals(Integer.toString(expectedData.length), fields.get("DataLength"));
      assertEquals("direct", fields.get("UploadFrom"));

      byte[] received = readExactly(input, expectedData.length);
      assertArrayEquals(expectedData, received);
    }

    void send(String messageName, Map<String, String> fields) throws IOException {
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      buffer.write((messageName + "\n").getBytes(StandardCharsets.UTF_8));
      for (Map.Entry<String, String> entry : fields.entrySet()) {
        buffer.write(
            (entry.getKey() + "=" + entry.getValue() + "\n").getBytes(StandardCharsets.UTF_8));
      }
      buffer.write("End\n".getBytes(StandardCharsets.UTF_8));
      output.write(buffer.toByteArray());
      output.flush();
    }

    private static Map<String, String> readFieldsUntilEnd(InputStream input) throws IOException {
      Map<String, String> fields = new HashMap<>();
      while (true) {
        String line = readLine(input);
        if ("End".equals(line)) {
          return fields;
        }
        int equals = line.indexOf('=');
        if (equals <= 0) {
          fields.put(line, "");
          continue;
        }
        fields.put(line.substring(0, equals), line.substring(equals + 1));
      }
    }

    private static Map<String, String> readFieldsUntilData(InputStream input) throws IOException {
      Map<String, String> fields = new HashMap<>();
      while (true) {
        String line = readLine(input);
        if ("Data".equals(line)) {
          return fields;
        }
        int equals = line.indexOf('=');
        if (equals <= 0) {
          fields.put(line, "");
          continue;
        }
        fields.put(line.substring(0, equals), line.substring(equals + 1));
      }
    }

    private static byte[] readExactly(InputStream input, int len) throws IOException {
      byte[] data = new byte[len];
      int offset = 0;
      while (offset < len) {
        int read = input.read(data, offset, len - offset);
        if (read < 0) {
          throw new IOException("Unexpected EOF while reading " + len + " bytes");
        }
        offset += read;
      }
      return data;
    }

    private static String readLine(InputStream input) throws IOException {
      ByteArrayOutputStream line = new ByteArrayOutputStream();
      while (true) {
        int b = input.read();
        if (b < 0) {
          throw new IOException("Unexpected EOF while reading line");
        }
        if (b == '\n') {
          break;
        }
        if (b != '\r') {
          line.write(b);
        }
      }
      return line.toString(StandardCharsets.UTF_8);
    }
  }
}
