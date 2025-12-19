package network.crypta.pluginmanager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.pluginmanager.PluginManager.PluginProgress;

/**
 * Plugin downloader implementation that reads a plugin artifact from a local file path.
 *
 * <p>This downloader is used when a plugin "source" is a filesystem location rather than a network
 * URL or a content-addressed identifier. It converts the provided source string to a {@link File},
 * derives the plugin name from the last path segment, and opens a {@link FileInputStream} so that
 * higher-level plugin installation code can stream the plugin bytes into its normal verification
 * and deployment pipeline.
 *
 * <p><strong>Notable behaviors</strong>
 *
 * <ul>
 *   <li>Always reports caching as prohibited, since the input is already local and should be read
 *       directly from disk.
 *   <li>Does not provide an SHA-1 checksum; callers must treat the source as unverified input and
 *       rely on their own integrity checks.
 *   <li>Does not support cancellation at the file-stream level; cancellation must be handled by the
 *       caller that owns the overall installation workflow.
 * </ul>
 *
 * <p><strong>Thread-safety:</strong> Instances are not documented as thread-safe. Callers should
 * treat an instance as single-use within a single installation attempt and avoid sharing it across
 * concurrent plugin operations.
 *
 * @see PluginDownLoader
 */
public class PluginDownLoaderFile extends PluginDownLoader<File> {

  /**
   * Creates a new downloader instance for local file sources.
   *
   * <p>The instance is configured later by the higher-level plugin download workflow, typically by
   * calling {@link #checkSource(String)} to validate and convert the provided source string into a
   * {@link File}. No filesystem I/O is performed by this constructor, and the object does not
   * retain any open resources until {@link #getInputStream(PluginProgress)} is invoked as part of
   * the installation flow.
   */
  public PluginDownLoaderFile() {
    /* Intentionally empty: this downloader is configured externally via checkSource(), and it does not
     * acquire resources until getInputStream(...) is called as part of the installation workflow.
     */
  }

  /**
   * Converts the provided source string into a {@link File} that will be used as the download
   * source.
   *
   * <p>This method performs only syntactic conversion; it does not check that the file exists, is
   * readable, or represents a valid plugin artifact. Callers are expected to handle any subsequent
   * validation and error reporting in the surrounding workflow. The returned {@link File} is used
   * by {@link #getInputStream(PluginProgress)} to open a stream for the plugin installation
   * pipeline.
   *
   * <p>This method is deterministic and side-effect free: repeated calls with the same input
   * produce equivalent {@link File} instances.
   *
   * @param source filesystem path to the plugin file, interpreted as-is without normalization
   * @return a {@link File} instance representing the given path, without probing the filesystem
   */
  @Override
  public File checkSource(String source) {
    return new File(source);
  }

  @Override
  InputStream getInputStream(PluginProgress progress) throws IOException {
    return new FileInputStream(getSource());
  }

  @Override
  String getPluginName(String source) throws PluginNotFoundException {
    int slashIndex = source.lastIndexOf('/');
    if (slashIndex == -1) slashIndex = source.lastIndexOf('\\');
    return source.substring(slashIndex + 1);
  }

  @Override
  String getSHA1sum() {
    return null;
  }

  @Override
  void tryCancel() {
    // Definitely not supported.
  }

  /**
   * Indicates whether caching is prohibited for this downloader.
   *
   * <p>For local file sources, caching is not useful: the plugin bytes can be read directly from
   * the filesystem, and duplicating the content would waste disk space without improving
   * reliability. The plugin manager may still perform its own integrity checks or staging, but it
   * should not attempt to populate or consult a downloader-level cache for this source type.
   *
   * @return {@code true} to indicate that caching must not be used for this downloader
   */
  @Override
  public boolean isCachingProhibited() {
    return true;
  }
}
