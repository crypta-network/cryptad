package org.sevenzip;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import org.sevenzip.compression.lzma.Decoder;
import org.sevenzip.compression.lzma.Encoder;

public class LzmaAlone {
  public static class CommandLine {
    public static final int K_ENCODE = 0;
    public static final int K_DECODE = 1;
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
      String sw = s.substring(1).toLowerCase();
      if (sw.isEmpty()) return false;
      try {
        return parseSwitch(sw);
      } catch (NumberFormatException e) {
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
            } catch (NumberFormatException e) {
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
    System.out.println(
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

  public static void main(String[] args) throws Exception {
    System.out.println("\nLZMA (Java) 4.61  2008-11-23\n");

    if (args.length < 1) {
      printHelp();
      return;
    }

    CommandLine params = new CommandLine();
    if (!params.parse(args)) {
      System.out.println("\nIncorrect command");
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
