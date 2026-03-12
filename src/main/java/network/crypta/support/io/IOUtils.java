package network.crypta.support.io;

import java.io.IOException;
import java.util.zip.ZipFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * I/O helpers for safely closing resources without leaking exceptions.
 *
 * <p>This utility provides {@code closeQuietly(...)} overloads that invoke {@code close()} on a
 * resource and suppress specified failures by logging them instead of throwing. The intent is to
 * make cleanup code robust in error paths and during best-effort shutdown.
 *
 * <p>Behavior by overload:
 *
 * <ul>
 *   <li>{@link #closeQuietly(AutoCloseable)} catches any {@link Exception} (including {@link
 *       RuntimeException}) thrown by {@code close()} and logs it at {@code ERROR}. It does not
 *       catch {@link Error} to avoid hiding serious JVM/linkage failures.
 *   <li>{@link #closeQuietly(ZipFile)} catches only {@link IOException} from {@link ZipFile#close}
 *       and logs it at {@code ERROR}. Other unchecked failures (e.g., {@link
 *       IllegalStateException}) and {@link Error} propagate.
 * </ul>
 *
 * <p>Side effects and guarantees:
 *
 * <ul>
 *   <li>Thread-safe: methods are stateless and may be called from any thread.
 *   <li>Null-safe: passing {@code null} performs no action and logs nothing.
 *   <li>Logging: failures are reported via SLF4J with the resource instance included in the message
 *       where available.
 * </ul>
 *
 * <p>Usage examples:
 *
 * <pre>{@code
 * // Classic finally block
 * InputStream in = null;
 * try {
 *   in = Files.newInputStream(path);
 *   ...
 * } finally {
 *   IOUtils.closeQuietly(in);
 * }
 *
 * // Prefer try-with-resources for new code
 * try (InputStream in = Files.newInputStream(path)) {
 *   ...
 * }
 * }</pre>
 */
public class IOUtils {
  private static final Logger LOG = LoggerFactory.getLogger(IOUtils.class);

  private IOUtils() {
    // Not instantiable: utility holder.
  }

  /**
   * Closes the provided {@link AutoCloseable} and logs any {@link Exception} thrown by {@code
   * close()}.
   *
   * <p>Semantics:
   *
   * <ul>
   *   <li>Null-safe: does nothing when {@code resource == null}.
   *   <li>Swallows and logs any checked or unchecked {@link Exception} at {@code ERROR} level.
   *   <li>Does not catch {@link Error}; such failures propagate to the caller.
   * </ul>
   *
   * <p>Threading: This method is thread-safe. It performs one synchronous {@code close()} call on
   * the provided instance.
   *
   * @param resource the resource to close; may be {@code null}
   * @throws Error if {@code close()} throws an {@code Error}; it is not intercepted intentionally
   */
  public static void closeQuietly(AutoCloseable resource) {
    if (resource != null) {
      try {
        resource.close();
      } catch (Exception e) { // Catch Exception (includes RuntimeException); Errors propagate.
        LOG.error("Error during close() on {}", resource, e);
      }
    }
  }

  /**
   * Closes the provided {@link ZipFile} and logs any {@link IOException} thrown by {@link
   * ZipFile#close()}.
   *
   * <p>Semantics:
   *
   * <ul>
   *   <li>Null-safe: does nothing when {@code zipFile == null}.
   *   <li>Swallows and logs {@link IOException} at {@code ERROR} level.
   *   <li>Does not catch other unchecked failures (e.g., {@link RuntimeException}) or {@link
   *       Error}; those propagate to the caller.
   * </ul>
   *
   * @param zipFile the zip file to close; may be {@code null}
   * @throws RuntimeException if {@code close()} throws a runtime exception; it is not intercepted
   * @throws Error if {@code close()} throws an {@code Error}; it is not intercepted
   */
  public static void closeQuietly(ZipFile zipFile) {
    if (zipFile != null) {
      try {
        zipFile.close();
      } catch (IOException e) { // Catch only IOExceptions; runtime exceptions and Errors propagate.
        LOG.error("Error during close() on ZipFile", e);
      }
    }
  }
}
