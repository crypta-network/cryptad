package network.crypta.tools;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import network.crypta.support.Logging;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.event.Level;

/**
 * Command-line utility that cleans up translation property files under {@code src/freenet/l10n}.
 *
 * <p>This tool treats {@code crypta.l10n.en.properties} as the reference set of translation keys
 * and rewrites other {@code crypta.l10n.*.properties} files to remove entries whose keys are no
 * longer present in the English file. It is intended for repository maintenance (e.g., after
 * renaming or deleting strings) so translators are not left with keys that are never looked up at
 * runtime.
 *
 * <p><b>Notable behaviors</b>:
 *
 * <ul>
 *   <li>Preserves the original line text for keys that are kept, including any value formatting.
 *   <li>Requires translation files to terminate with a single {@code End} line and no trailing
 *       content.
 *   <li>Exits the JVM with a non-zero status for structural errors or I/O failures.
 * </ul>
 *
 * <p>This class performs file I/O and is not designed for concurrent use across multiple processes
 * targeting the same directory; it makes no attempt at locking or atomic multi-file updates.
 *
 * @see SimpleFieldSet
 * @see Logging
 */
public class CleanupTranslations {
  private static final PrintWriter STDOUT =
      new PrintWriter(
          new OutputStreamWriter(new FileOutputStream(FileDescriptor.out), StandardCharsets.UTF_8),
          true);
  private static final PrintWriter STDERR =
      new PrintWriter(
          new OutputStreamWriter(new FileOutputStream(FileDescriptor.err), StandardCharsets.UTF_8),
          true);

  /**
   * Removes translation keys that are no longer present in the English reference file.
   *
   * <p>The tool loads {@code src/freenet/l10n/crypta.l10n.en.properties} as a {@link
   * SimpleFieldSet} and scans files in {@code src/freenet/l10n}. For each translation file, it
   * keeps only key/value lines whose key exists in the English file and then rewrites the
   * translation file if any orphaned keys were removed. Structural issues (such as missing {@code
   * End} terminators) are treated as fatal and cause the JVM to exit with a non-zero status code.
   *
   * <p>This method performs filesystem reads and writes and is expected to be run as a single-shot
   * CLI command. It is not idempotent with respect to formatting because it rewrites the file
   * content exactly as it was read for kept lines.
   *
   * @param args command-line arguments, currently ignored by this maintenance utility
   * @throws IOException if reading or writing translation files fails with an I/O error
   */
  public static void main(String[] args) throws IOException {
    Logging.bootstrap(Level.ERROR, "");
    File engFile = new File("src/freenet/l10n/crypta.l10n.en.properties");
    SimpleFieldSet english = SimpleFieldSet.readFrom(engFile, false, true);
    File translationDir = new File("src/freenet/l10n");
    File[] translations = translationDir.listFiles();
    if (translations == null) {
      fail(3, "Unable to list translation files in: " + translationDir);
    } else {
      for (File translation : translations) {
        if (isTranslationFile(translation)) {
          CleanupResult result = cleanupTranslationFile(translation, english);
          if (result.changed()) {
            try (FileOutputStream fos = new FileOutputStream(translation);
                OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8)) {
              osw.write(result.content());
            }
            STDOUT.println("Rewritten " + translation);
          }
        }
      }
    }
  }

  /**
   * Creates a new instance.
   *
   * <p>This type is primarily used via its {@link #main(String[])} entry point and carries no
   * instance state. The explicit constructor exists only to satisfy strict doclint checks for the
   * public default constructor.
   */
  public CleanupTranslations() {
    // Intentionally empty: this utility is invoked via main(...) and has no instance state.
  }

  private static boolean isTranslationFile(File file) {
    String name = file.getName();
    return name.startsWith("crypta.l10n.") && !name.equals("crypta.1l0n.en.properties");
  }

  private static CleanupResult cleanupTranslationFile(File file, SimpleFieldSet english)
      throws IOException {
    StringWriter output = new StringWriter();
    boolean changed = false;

    try (FileInputStream fis = new FileInputStream(file);
        InputStreamReader isr =
            new InputStreamReader(new BufferedInputStream(fis), StandardCharsets.UTF_8);
        BufferedReader br = new BufferedReader(isr)) {
      boolean finished = false;
      while (!finished) {
        String line = br.readLine();
        if (line == null) {
          fail(4, "File does not end in End: " + file);
        } else {
          int idx = line.indexOf('=');
          if (idx == -1) {
            finished = handleEndLine(line, br, output, file);
          } else {
            changed |= handleKeyLine(line, idx, english, output, file);
          }
        }
      }
    }

    return new CleanupResult(changed, output.toString());
  }

  private static boolean handleEndLine(
      String line, BufferedReader br, StringWriter output, File file) throws IOException {
    if (!line.equals("End")) {
      fail(1, "Line with no equals (file does not end in End???): " + file + " - \"" + line + "\"");
    }

    output.append(line).append("\n");
    String extra = br.readLine();
    if (extra != null) {
      fail(2, "Content after End: \"" + extra + "\"");
    }

    return true;
  }

  private static boolean handleKeyLine(
      String line, int equalsIndex, SimpleFieldSet english, StringWriter output, File file) {
    String key = line.substring(0, equalsIndex);
    if (english.get(key) == null) {
      STDERR.println("Orphaned string: \"" + key + "\" in " + file);
      return true;
    }

    output.append(line).append("\n");
    return false;
  }

  private static void fail(int exitCode, String message) {
    STDERR.println(message);
    System.exit(exitCode);
    throw new IllegalStateException(message);
  }

  private record CleanupResult(boolean changed, String content) {}
}
