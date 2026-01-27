package org.sevenzip;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;

/**
 * Standalone entry point for running LZMA compression, decompression, and micro-benchmarks from the
 * command line. The class parses a small switch-based argument syntax, configures encoder or + *
 * decoder instances, and streams data between files without loading them entirely into memory.
 *
 * <p>Typical usage is through {@link #main(String[])} by invoking the packaged jar with either
 * encode ({@code e}), decode ({@code d}), or benchmark ({@code b}) modes, followed by optional
 * tuning flags. The implementation favors deterministic behavior: it sets all tunables explicitly
 * and relies on buffered streams to limit memory pressure on large inputs. Operations are
 * synchronous and block until completion; no background threads are started.
 *
 * <p>Thread safety: this class maintains no shared mutable state beyond logger configuration and is
 * intended to be used as a single-process tool. Creating multiple instances concurrently is not a
 * supported pattern; prefer separate JVM invocations if parallel execution is required.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Parsing command-line switches into a {@link CommandLine} model.
 *   <li>Configuring encoder/decoder instances and orchestrating streaming I/O.
 *   <li>Printing user-facing help and reporting basic argument errors.
 * </ul>
 */
public class LzmaAlone {

  /**
   * Constructs a new instance of the tool facade. Instantiation is rarely required because all
   * primary entry points are static, but the constructor remains available for frameworks that rely
   * on reflective creation.
   */
  public LzmaAlone() {
    // Intentionally empty: provided for reflective construction in tooling that expects a public
    // no-arg entry point.
  }

  private static final Logger LOGGER = Logger.getLogger(LzmaAlone.class.getName());

  static {
    Handler handler = new SystemOutHandler();
    LOGGER.setUseParentHandlers(false);
    LOGGER.addHandler(handler);
    LOGGER.setLevel(Level.INFO);
  }

  static void setLogStream(PrintStream stream) {
    SystemOutHandler.setLogStream(stream);
  }

  static PrintStream getLogStream() {
    return SystemOutHandler.getLogStream();
  }

  private static final class SystemOutHandler extends Handler {
    private static final AtomicReference<PrintStream> LOG_STREAM =
        new AtomicReference<>(new PrintStream(new FileOutputStream(FileDescriptor.out)));
    private final SimpleFormatter formatter = new SimpleFormatter();

    SystemOutHandler() {
      setLevel(Level.INFO);
    }

    @Override
    public synchronized void publish(LogRecord logRecord) {
      if (!isLoggable(logRecord)) {
        return;
      }
      LOG_STREAM.get().print(formatter.format(logRecord));
    }

    @Override
    public void flush() {
      LOG_STREAM.get().flush();
    }

    @Override
    public void close() {
      // nothing to close; System.out is managed externally
    }

    static void setLogStream(PrintStream stream) {
      LOG_STREAM.set(stream);
    }

    static PrintStream getLogStream() {
      return LOG_STREAM.get();
    }
  }

  /**
   * Parsed command-line options for LZMA standalone invocations. This mutable holder captures the
   * requested operation (encode, decode, benchmark), file paths, dictionary and match-finder
   * parameters, and optional end-of-stream handling.
   *
   * <p>The parser is intentionally permissive: switches may precede positional arguments and are
   * case-insensitive where appropriate. Fields are populated only after successful parsing; callers
   * should always check the boolean result of {@link #parse(String[])} before reading values. The
   * instance is not thread-safe and is meant to be confined to the parsing flow of a single
   * invocation.
   */
  public static class CommandLine {

    /**
     * Creates an empty command-line model with defaults matching the original LZMA SDK tool. Values
     * remain unset until {@link #parse(String[])} completes successfully.
     */
    public CommandLine() {
      // Intentionally empty: instances are populated via parse(String[]) after creation.
    }

    /**
     * Mode constant for LZMA compression of the provided input file to the output file, producing a
     * stream with embedded coder properties and optional end-of-stream marker suitable for later
     * decoding by compatible tools.
     */
    public static final int K_ENCODE = 0;

    /**
     * Mode constant for LZMA decompression of the provided input file to the output file; expects
     * the input to begin with coder properties and an eight-byte size header emitted by encode
     * runs.
     */
    public static final int K_DECODE = 1;

    /**
     * Mode constant triggering the built-in benchmark, which runs several encode/decode passes
     * against generated data to estimate throughput; the integer operand controls pass count and
     * defaults to ten iterations when omitted.
     */
    public static final int K_BENCHMARK = 2;

    private int command = -1;
    private int numBenchmarkPasses = 10;

    private int dictionarySize = 1 << 23;
    private boolean dictionarySizeIsDefined = false;

    private int lc = 3;
    private int lp = 0;
    private int pb = 2;

    private int fb = 128;

    private boolean eos = false;

    private int algorithm = 2;
    private int matchFinder = 1;

    private String inFile;
    private String outFile;

    boolean parseSwitch(String s) {
      if (s.startsWith("d")) {
        dictionarySize = 1 << Integer.parseInt(s.substring(1));
        dictionarySizeIsDefined = true;
      } else if (s.startsWith("fb")) {
        fb = Integer.parseInt(s.substring(2));
      } else if (s.startsWith("a")) algorithm = Integer.parseInt(s.substring(1));
      else if (s.startsWith("lc")) lc = Integer.parseInt(s.substring(2));
      else if (s.startsWith("lp")) lp = Integer.parseInt(s.substring(2));
      else if (s.startsWith("pb")) pb = Integer.parseInt(s.substring(2));
      else if (s.startsWith("eos")) eos = true;
      else if (s.startsWith("mf")) {
        String mfs = s.substring(2);
        switch (mfs) {
          case "bt2":
            matchFinder = 0;
            break;
          case "bt4":
            matchFinder = 1;
            break;
          case "bt4b":
            matchFinder = 2;
            break;
          default:
            return false;
        }
      } else return false;
      return true;
    }

    /**
     * Parses the provided argument list into this instance, respecting both switch tokens (prefixed
     * with {@code -}) and positional parameters.
     *
     * @param args full argument array as received by {@link LzmaAlone#main(String[])}, not null;
     *     entries may include switches and up to two positional file paths depending on the mode.
     * @return {@code true} when parsing succeeds and the command plus required operands are
     *     populated; {@code false} when any token is invalid or required operands are missing.
     */
    public boolean parse(String[] args) {
      ParseState state = new ParseState(true, 0);
      for (String s : args) {
        if (!processArg(s, state)) return false;
      }
      return true;
    }

    private static final class ParseState {
      boolean switchMode;
      int pos;

      ParseState(boolean switchMode, int pos) {
        this.switchMode = switchMode;
        this.pos = pos;
      }
    }

    private boolean processArg(String s, ParseState state) {
      if (s.isEmpty()) return false;
      if (state.switchMode && isSwitchToken(s)) {
        return processSwitchToken(s, state);
      }
      int next = processPositional(s, state.pos);
      if (next < 0) return false;
      state.pos = next;
      return true;
    }

    private boolean processSwitchToken(String s, ParseState state) {
      if ("--".equals(s)) {
        state.switchMode = false;
        return true;
      }
      String sw = s.substring(1).toLowerCase(Locale.ROOT);
      if (sw.isEmpty()) return false;
      try {
        return parseSwitch(sw);
      } catch (NumberFormatException _) {
        return false;
      }
    }

    private static boolean isSwitchToken(String s) {
      return s.charAt(0) == '-' || "--".equals(s);
    }

    private int processPositional(String s, int pos) {
      return switch (pos) {
        case 0 -> {
          if (s.equalsIgnoreCase("e")) command = K_ENCODE;
          else if (s.equalsIgnoreCase("d")) command = K_DECODE;
          else if (s.equalsIgnoreCase("b")) command = K_BENCHMARK;
          else yield -1;
          yield 1;
        }
        case 1 -> {
          if (command == K_BENCHMARK) {
            try {
              numBenchmarkPasses = Integer.parseInt(s);
              if (numBenchmarkPasses < 1) yield -1;
            } catch (NumberFormatException _) {
              yield -1;
            }
          } else {
            inFile = s;
          }
          yield 2;
        }
        case 2 -> {
          outFile = s;
          yield 3;
        }
        default -> -1;
      };
    }
  }

  static void printHelp() {
    LOGGER.info(
        """

            Usage:  LZMA <e|d> [<switches>...] inputFile outputFile
              e: encode file
              d: decode file
              b: Benchmark
            <Switches>
          -d{N}:  set dictionary - [0,28], default: 23 (8MB)
          -fb{N}: set number of fast bytes - [5, 273], default: 128
          -lc{N}: set number of literal context bits - [0, 8], default: 3
          -lp{N}: set number of literal pos bits - [0, 4], default: 0
          -pb{N}: set number of pos bits - [0, 4], default: 2
          -mf{MF_ID}: set Match Finder: [bt2, bt4], default: bt4
          -eos:   write End Of Stream marker
        """);
  }

  /**
   * Application entry point wiring the command-line interface to encoding, decoding, or benchmark
   * flows. Invokes {@link CommandLine#parse(String[])} to interpret arguments and dispatches to the
   * appropriate handler.
   *
   * <p>Expected usage patterns:
   *
   * <ul>
   *   <li>{@code LzmaAlone e input.bin output.lzma} – compresses a file.
   *   <li>{@code LzmaAlone d input.lzma output.bin} – decompresses a file.
   *   <li>{@code LzmaAlone b 5} – runs five benchmark passes to gauge performance.
   * </ul>
   *
   * When argument validation fails, the method prints guidance and exits without throwing. IO
   * failures or unsupported option combinations propagate as runtime exceptions aligned with the
   * underlying encoder/decoder.
   *
   * @param args raw command-line tokens defining the mode and file operands; may be empty to show
   *     usage guidance.
   * @throws Exception when IO operations, codec configuration, or benchmark execution fail; callers
   *     rely on process exit handling for reporting.
   */
  public static void main(String[] args) throws Exception {
    LOGGER.info("\nLZMA (Java) 4.61  2008-11-23\n");

    if (args.length < 1) {
      printHelp();
      return;
    }

    CommandLine params = new CommandLine();
    if (!params.parse(args)) {
      LOGGER.info("\nIncorrect command");
      return;
    }

    switch (params.command) {
      case CommandLine.K_BENCHMARK:
        handleBenchmark(params);
        break;
      case CommandLine.K_ENCODE:
        encode(params);
        break;
      case CommandLine.K_DECODE:
        decode(params);
        break;
      default:
        throw new IllegalArgumentException("Incorrect command");
    }
  }

  private static void handleBenchmark(CommandLine params) throws IOException {
    int dictionary = (1 << 21);
    if (params.dictionarySizeIsDefined) dictionary = params.dictionarySize;
    if (params.matchFinder > 1) throw new IllegalArgumentException("Unsupported match finder");
    LzmaBench.lzmaBenchmark(params.numBenchmarkPasses, dictionary);
  }

  private static void encode(CommandLine params) throws IOException {
    File inFile = new File(params.inFile);
    File outFile = new File(params.outFile);
    try (BufferedInputStream inStream = new BufferedInputStream(new FileInputStream(inFile));
        BufferedOutputStream outStream = new BufferedOutputStream(new FileOutputStream(outFile))) {
      boolean eos = params.eos;
      Encoder encoder = createConfiguredEncoder(params, eos);
      encoder.writeCoderProperties(outStream);
      long fileSize;
      if (eos) fileSize = -1;
      else fileSize = inFile.length();
      for (int i = 0; i < 8; i++) outStream.write((int) (fileSize >>> (8 * i)) & 0xFF);
      encoder.code(inStream, outStream, null);
    }
  }

  private static Encoder createConfiguredEncoder(CommandLine params, boolean eos) {
    Encoder encoder = new Encoder();
    if (!encoder.setAlgorithm(params.algorithm))
      throw new IllegalArgumentException("Incorrect compression mode");
    if (!encoder.setDictionarySize(params.dictionarySize))
      throw new IllegalArgumentException("Incorrect dictionary size");
    if (!encoder.setNumFastBytes(params.fb))
      throw new IllegalArgumentException("Incorrect -fb value");
    if (!encoder.setMatchFinder(params.matchFinder))
      throw new IllegalArgumentException("Incorrect -mf value");
    if (!encoder.setLcLpPb(params.lc, params.lp, params.pb))
      throw new IllegalArgumentException("Incorrect -lc or -lp or -pb value");
    encoder.setEndMarkerMode(eos);
    return encoder;
  }

  private static void decode(CommandLine params) throws IOException {
    File inFile = new File(params.inFile);
    File outFile = new File(params.outFile);
    try (BufferedInputStream inStream = new BufferedInputStream(new FileInputStream(inFile));
        BufferedOutputStream outStream = new BufferedOutputStream(new FileOutputStream(outFile))) {
      int propertiesSize = 5;
      byte[] properties = new byte[propertiesSize];
      if (inStream.read(properties, 0, propertiesSize) != propertiesSize)
        throw new IllegalArgumentException("input .lzma file is too short");
      Decoder decoder = new Decoder();
      if (!decoder.setDecoderProperties(properties))
        throw new IllegalArgumentException("Incorrect stream properties");
      long outSize = 0;
      for (int i = 0; i < 8; i++) {
        int v = inStream.read();
        if (v < 0) throw new IllegalArgumentException("Can't read stream size");
        outSize |= ((long) v) << (8 * i);
      }
      if (!decoder.code(inStream, outStream, outSize))
        throw new IllegalArgumentException("Error in data stream");
    }
  }
}
