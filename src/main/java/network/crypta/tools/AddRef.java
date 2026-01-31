package network.crypta.tools;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.filter.LevelFilter;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import ch.qos.logback.core.spi.FilterReply;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import network.crypta.clients.fcp.AddPeer;
import network.crypta.clients.fcp.FCPMessage;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.MessageInvalidException;
import network.crypta.clients.fcp.NodeHelloMessage;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.LineReadingInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Command-line tool that adds a darknet reference to a running local node via FCP.
 *
 * <p>This class is intended to be invoked from the command line with a single argument pointing to
 * a reference file. It connects to the local {@link network.crypta.clients.fcp.FCPServer} on the
 * default port, performs a minimal FCP handshake (sending {@code ClientHello} and validating the
 * node responds with {@code NodeHello}), and then sends the parsed reference fields using the
 * {@code AddPeer} message.
 *
 * <p>The implementation is intentionally small and synchronous: it opens one TCP connection, sends
 * a small number of messages, and exits. It logs user-facing output to stdout/stderr and, for
 * historical compatibility with existing scripts, exits the JVM with a non-zero code on common
 * failure paths (invalid arguments, connection failures, or I/O errors). This tool is not designed
 * for concurrent use; each invocation operates independently and has no shared mutable state.
 *
 * <ul>
 *   <li><b>Inputs:</b> a readable file containing a serialized {@link SimpleFieldSet} reference
 *   <li><b>Outputs:</b> a best-effort attempt to add the reference, reported via logs
 *   <li><b>Failure modes:</b> validation errors, socket errors, or malformed message data
 * </ul>
 *
 * @see network.crypta.clients.fcp.FCPMessage
 * @see network.crypta.clients.fcp.NodeHelloMessage
 * @see network.crypta.clients.fcp.AddPeer
 */
public class AddRef {
  private static final Logger LOG = LoggerFactory.getLogger(AddRef.class);

  private AddRef() {}

  /**
   * Runs the AddRef command-line entry point, validating arguments and executing the adding flow.
   *
   * <p>This method configures console logging suitable for standalone execution, validates that a
   * reference file path is provided and readable, and then attempts to connect to the local FCP
   * server to submit the reference. On invalid arguments the process exits immediately; on network
   * or I/O failures, errors are logged and the process exits with a non-zero status. The tool
   * intentionally sleeps briefly at shutdown to make user-facing console output easier to observe
   * when launched from wrappers that may close quickly.
   *
   * @param args command-line arguments where {@code args[0]} is a readable reference file path
   *     suitable for {@link SimpleFieldSet#readFrom(File, boolean, boolean)}.
   */
  public static void main(String[] args) {
    configureStandaloneConsoleLogging();
    if (args.length < 1) {
      LOG.error("Please provide a file name as the first argument.");
      System.exit(-1);
    }

    final File reference = new File(args[0]);
    if (!reference.isFile() || !reference.canRead()) {
      LOG.error("Please provide a file name as the first argument.");
      System.exit(-1);
    }

    addRef(reference);
  }

  private static void addRef(File reference) {
    try {
      try (Socket fcpSocket = openFcpSocket();
          LineReadingInputStream lis = new LineReadingInputStream(fcpSocket.getInputStream());
          OutputStream os = fcpSocket.getOutputStream()) {
        fcpSocket.setSoTimeout(2000);
        sendClientHelloAndValidateNode(lis, os);
        sendReference(reference, os);
      }
      LOG.info("That reference has been added");
    } catch (SocketException se) {
      LOG.error("Failed to connect to FCP server.", se);
      System.exit(1);
    } catch (IOException ioe) {
      LOG.error("I/O error while communicating with the FCP server.", ioe);
      System.exit(2);
    } finally {
      sleepAtShutdown();
    }
  }

  private static Socket openFcpSocket() throws IOException {
    IOException lastException = null;
    for (String host : new String[] {"127.0.0.1", "::1"}) {
      try {
        return new Socket(InetAddress.getByName(host), FCPServer.DEFAULT_FCP_PORT);
      } catch (IOException e) {
        lastException = e;
      }
    }
    if (lastException != null) {
      throw lastException;
    }
    throw new SocketException("No loopback addresses available");
  }

  private static void sendClientHelloAndValidateNode(LineReadingInputStream lis, OutputStream os)
      throws IOException {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Name", "AddRef");
    sfs.putSingle("ExpectedVersion", "2.0");
    try {
      FCPMessage fcpm = FCPMessage.create("ClientHello", sfs);
      fcpm.send(os);
      os.flush();

      String messageName = lis.readLine(128, 128, true);
      sfs = getMessage(lis);
      fcpm = FCPMessage.create(messageName, sfs);
      if (!(fcpm instanceof NodeHelloMessage)) {
        LOG.error("Not a valid FRED node!");
        System.exit(1);
      }
    } catch (MessageInvalidException e) {
      LOG.error("Received an invalid FCP message during node handshake.", e);
    }
  }

  private static void sendReference(File reference, OutputStream os) throws IOException {
    try {
      SimpleFieldSet sfs = SimpleFieldSet.readFrom(reference, false, true);
      FCPMessage fcpm = FCPMessage.create(AddPeer.NAME, sfs);
      fcpm.send(os);
      os.flush();
    } catch (MessageInvalidException e) {
      LOG.error("Invalid reference file.", e);
    }
  }

  private static void sleepAtShutdown() {
    try {
      Thread.sleep(3000);
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
  }

  /**
   * Reads an FCP message body from the provided line reader into a {@link SimpleFieldSet}.
   *
   * <p>This helper performs a best-effort parse of {@code key=value} lines that follow an FCP
   * message name. Reading stops when the stream reports no more available bytes, when a line begins
   * with {@code End}, or when a line cannot be split on {@code '='}. The returned field set may be
   * empty or partially populated if the peer closes the connection early or an I/O error occurs.
   *
   * <p>This method does not throw checked exceptions. If an {@link IOException} occurs while
   * reading, the error is logged and the fields collected so far are returned.
   *
   * @param lis line-oriented view of the underlying FCP socket input, positioned at the start of
   *     the message field lines.
   * @return a {@link SimpleFieldSet} containing any successfully parsed fields, possibly empty.
   */
  protected static SimpleFieldSet getMessage(LineReadingInputStream lis) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    try {
      while (lis.available() > 0) {
        String line = lis.readLine(128, 128, true);
        int index = line.indexOf('=');
        if (index == -1 || line.startsWith("End")) return sfs;
        sfs.putSingle(line.substring(0, index), line.substring(index + 1));
      }
    } catch (IOException e) {
      LOG.error("Failed while reading an FCP message.", e);
      return sfs;
    }

    return sfs;
  }

  /**
   * Ensures AddRef emits user-facing output to stdout/stderr (plain text) when running as a
   * standalone tool.
   *
   * <p>In particular, tests execute AddRef in a separate JVM where the default Logback
   * configuration may route console logs to stdout only. This method configures the AddRef logger
   * to emit INFO to stdout and ERROR to stderr, matching historical behavior.
   */
  private static void configureStandaloneConsoleLogging() {
    if (!(LoggerFactory.getILoggerFactory() instanceof LoggerContext context)) {
      return;
    }

    ch.qos.logback.classic.Logger logger = context.getLogger(AddRef.class);
    if (logger.getAppender("ADDREF_OUT") != null || logger.getAppender("ADDREF_ERR") != null) {
      return;
    }

    logger.setAdditive(false);
    logger.detachAndStopAllAppenders();

    ConsoleAppender<ILoggingEvent> stdout = new ConsoleAppender<>();
    stdout.setName("ADDREF_OUT");
    stdout.setContext(context);
    stdout.setTarget("System.out");
    stdout.setEncoder(newConsoleEncoder(context, "%msg%n"));
    stdout.addFilter(levelOnlyFilter(ch.qos.logback.classic.Level.INFO));
    stdout.start();
    logger.addAppender(stdout);

    ConsoleAppender<ILoggingEvent> stderr = new ConsoleAppender<>();
    stderr.setName("ADDREF_ERR");
    stderr.setContext(context);
    stderr.setTarget("System.err");
    stderr.setEncoder(newConsoleEncoder(context, "%msg%n%ex{full}"));
    stderr.addFilter(levelOnlyFilter(ch.qos.logback.classic.Level.ERROR));
    stderr.start();
    logger.addAppender(stderr);

    logger.setLevel(ch.qos.logback.classic.Level.INFO);
  }

  private static PatternLayoutEncoder newConsoleEncoder(LoggerContext context, String pattern) {
    PatternLayoutEncoder encoder = new PatternLayoutEncoder();
    encoder.setContext(context);
    encoder.setPattern(pattern);
    encoder.start();
    return encoder;
  }

  private static LevelFilter levelOnlyFilter(ch.qos.logback.classic.Level level) {
    LevelFilter filter = new LevelFilter();
    filter.setLevel(level);
    filter.setOnMatch(FilterReply.ACCEPT);
    filter.setOnMismatch(FilterReply.DENY);
    filter.start();
    return filter;
  }
}
