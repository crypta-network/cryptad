package network.crypta.platform.webshell;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Helper for reading shell-owned classpath resources.
 *
 * <p>The platform web-shell leaf stores its HTML, CSS, and JavaScript as plain resources bundled in
 * the application classpath. This helper centralizes the small amount of I/O needed to read those
 * files so the rest of the shell code can stay focused on routing, bootstrap modeling, and page
 * rendering. Callers do not have to repeat resource-stream setup, UTF-8 decoding, or missing-file
 * checks at every use site.
 *
 * <p>The helper intentionally exposes only text loading for the current shell. That matches the v1
 * asset set and keeps the API narrow while the shell remains dependency-light. If later shell work
 * needs binary assets or streaming responses, that can be added in one place without leaking
 * resource-loading details through the rest of the package.
 */
public final class WebShellResources {
  /** Prevents instantiation of this static helper. */
  private WebShellResources() {}

  /**
   * Reads one shell-owned classpath resource as UTF-8 text.
   *
   * <p>The path must be an absolute classpath location such as the values exposed by {@code
   * WebShellPaths}. Missing resources and low-level I/O failures are surfaced as {@link
   * IllegalStateException} because the shell assets are packaged application resources rather than
   * user-controlled inputs. A failure here indicates a broken build or classpath, not a normal
   * runtime condition the caller can recover from locally.
   *
   * @param resourcePath absolute classpath resource path
   * @return resource contents as a single text string
   * @throws NullPointerException if {@code resourcePath} is {@code null}
   * @throws IllegalStateException if the resource is missing or cannot be read
   */
  public static String readText(String resourcePath) {
    Objects.requireNonNull(resourcePath, "resourcePath");
    try (InputStream in = WebShellResources.class.getResourceAsStream(resourcePath)) {
      if (in == null) {
        throw new IllegalStateException("Missing Web Shell resource: " + resourcePath);
      }
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read Web Shell resource: " + resourcePath, e);
    }
  }
}
