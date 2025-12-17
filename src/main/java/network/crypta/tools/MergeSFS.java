package network.crypta.tools;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import network.crypta.support.SimpleFieldSet;

/**
 * Merge a {@link SimpleFieldSet} “override” file into a “source” file.
 *
 * <p>This tool reads two SimpleFieldSet (SFS) documents, applies all keys from the override onto
 * the source using {@link SimpleFieldSet#putAllOverwrite(SimpleFieldSet)}, and writes the merged
 * result back in deterministic key order. It is primarily a small command-line utility, but the
 * core behavior is exposed as stream-based methods so it can be exercised in unit tests without
 * creating temporary files.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Encoding is treated as UTF-8 for both reading and writing.
 *   <li>The merge is an overwrite merge: if a key exists in both inputs, the override wins.
 *   <li>Output uses {@link SimpleFieldSet#writeToOrdered(Writer)} for stable ordering.
 * </ul>
 *
 * <p>Thread-safety and mutability: this class is stateless. The {@link #merge(InputStream,
 * InputStream, OutputStream)} method creates new {@link SimpleFieldSet} instances from the input
 * streams. The {@link #mergeInPlace(SimpleFieldSet, SimpleFieldSet)} method mutates the provided
 * {@code source} instance.
 */
public class MergeSFS {

  private MergeSFS() {}

  /**
   * Run the command-line merge tool.
   *
   * <p>This method expects two file paths: the source file to merge into and an override file whose
   * keys overwrite matching keys in the source. If a third argument equal to {@code --stdout} is
   * provided, the merged result is written to standard output; otherwise the source file is
   * overwritten in place. When the arguments are invalid, usage information is written and the
   * method returns without modifying any file.
   *
   * @param args command-line arguments: {@code source-file override-file [--stdout]} in that order.
   * @throws IOException if reading either file or writing the merged output fails.
   */
  public static void main(String[] args) throws IOException {
    if (args.length < 2 || args.length > 3) {
      try (OutputStream out = stdoutOutputStream()) {
        printUsage(out);
      }
      return;
    }
    File f1 = new File(args[0]);
    File f2 = new File(args[1]);
    boolean useStdout = args.length == 3 && "--stdout".equals(args[2]);

    if (useStdout) {
      try (InputStream sourceIn = new FileInputStream(f1);
          InputStream overrideIn = new FileInputStream(f2);
          OutputStream out = stdoutOutputStream()) {
        merge(sourceIn, overrideIn, out);
      }
      return;
    }

    // Important: Do not open the output stream to f1 until after the source has been parsed.
    // Constructing FileOutputStream(f1) truncates f1 immediately, which would otherwise zero the
    // source file before we read it, resulting in a merge that only contains the override.
    SimpleFieldSet source;
    SimpleFieldSet override;
    try (InputStream sourceIn = new FileInputStream(f1);
        InputStream overrideIn = new FileInputStream(f2)) {
      source = SimpleFieldSet.readFrom(sourceIn, false, true);
      override = SimpleFieldSet.readFrom(overrideIn, false, true);
    }
    mergeInPlace(source, override);
    try (OutputStream out = new FileOutputStream(f1)) {
      writeToOrderedUtf8(source, out);
    }
  }

  /**
   * Merge two UTF-8 encoded SFS streams and write the merged field set in deterministic order to
   * the given output stream.
   *
   * <p>This method does not close {@code out}. Note that {@link
   * SimpleFieldSet#readFrom(InputStream, boolean, boolean)} closes its {@link InputStream}
   * argument, so both {@code sourceIn} and {@code overrideIn} are closed as part of parsing.
   *
   * <p>The merge is performed by overwriting keys in the parsed source with keys from the parsed
   * override and then emitting the result via {@link SimpleFieldSet#writeToOrdered(Writer)}. The
   * output always includes the trailing end marker line (typically {@code End}).
   *
   * <pre>{@code
   * byte[] sourceBytes = "a=1\nEnd\n".getBytes(StandardCharsets.UTF_8);
   * byte[] overrideBytes = "b=2\nEnd\n".getBytes(StandardCharsets.UTF_8);
   * ByteArrayOutputStream out = new ByteArrayOutputStream();
   * MergeSFS.merge(new ByteArrayInputStream(sourceBytes), new ByteArrayInputStream(overrideBytes), out);
   * }</pre>
   *
   * @param sourceIn source SFS content to parse and then merge into, read and then closed.
   * @param overrideIn override SFS content whose keys overwrite the source, read and then closed.
   * @param out destination for the merged SFS text encoded as UTF-8, not closed by this method.
   * @throws IOException if parsing either input or writing the merged result fails.
   */
  public static void merge(InputStream sourceIn, InputStream overrideIn, OutputStream out)
      throws IOException {
    SimpleFieldSet source = SimpleFieldSet.readFrom(sourceIn, false, true);
    SimpleFieldSet override = SimpleFieldSet.readFrom(overrideIn, false, true);
    mergeInPlace(source, override);
    writeToOrderedUtf8(source, out);
  }

  /**
   * Apply all keys from {@code override} onto {@code source}, overwriting existing keys.
   *
   * <p>This is a small convenience wrapper around {@link
   * SimpleFieldSet#putAllOverwrite(SimpleFieldSet)}. It mutates {@code source} in place and returns
   * the same instance for fluent call sites. If {@code override} is {@code null}, no changes are
   * made.
   *
   * @param source base field set to modify in place; must not be {@code null}.
   * @param override overrides to apply on top of {@code source}; {@code null} performs no merge.
   * @return the same {@code source} instance after applying all override keys.
   */
  public static SimpleFieldSet mergeInPlace(SimpleFieldSet source, SimpleFieldSet override) {
    if (override != null) {
      source.putAllOverwrite(override);
    }
    return source;
  }

  private static void printUsage(OutputStream out) throws IOException {
    Writer w = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
    w.write("Merges changes made in a SFS override file to a SFS source file.\n");
    w.write("Usage: source-file override-file [--stdout]\n");
    w.write("    By default the merged file is written to source-file.\n");
    w.write("    --stdout writes to standard output instead.\n");
    w.flush();
  }

  private static void writeToOrderedUtf8(SimpleFieldSet fieldSet, OutputStream out)
      throws IOException {
    // Force output to UTF-8.
    Writer w = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
    fieldSet.writeToOrdered(w);
    w.flush();
  }

  @SuppressWarnings("java:S106")
  private static OutputStream stdoutOutputStream() {
    // Wrap System.out so try-with-resources callers can "close" it without closing stdout (FD 1).
    // Do not create a new FileOutputStream(FileDescriptor.out) here: if the stream is not closed,
    // its cleaner/finalizer may eventually close the shared stdout file descriptor during GC.
    return new FilterOutputStream(System.out) {
      @Override
      public void close() throws IOException {
        flush();
      }
    };
  }
}
