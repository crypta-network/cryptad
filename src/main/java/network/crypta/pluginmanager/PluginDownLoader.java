package network.crypta.pluginmanager;

import java.io.IOException;
import java.io.InputStream;
import network.crypta.pluginmanager.PluginManager.PluginProgress;

/**
 * Downloads plugin content from a specific source representation.
 *
 * <p>A {@code PluginDownLoader} is a small, state-carrying strategy object used by the plugin
 * manager to resolve a user-supplied source string into a validated, typed source object and then
 * provide an {@link InputStream} for the plugin bytes. Typical usage is to call {@link
 * #setSource(String)} once to validate and store the resolved source, then call {@link
 * #getInputStream(PluginProgress)} to stream the plugin payload. Implementations are also expected
 * to expose a human-readable plugin name and an integrity identifier where available.
 *
 * <p>This type is intentionally minimal and does not impose caching policy, official-vs-unofficial
 * classification, or where the bytes come from; those decisions are delegated to subclasses and the
 * caller. Instances are generally mutable due to {@link #setSource(String)} and should be treated
 * as not thread-safe unless a specific implementation documents otherwise.
 *
 * <ul>
 *   <li><b>Validation:</b> Convert and validate the raw source string into a typed source.
 *   <li><b>Streaming:</b> Provide an input stream for the plugin download.
 *   <li><b>Cancellation:</b> Best-effort cancellation via {@link #tryCancel()}.
 * </ul>
 *
 * @author saces
 * @param <T> Type of the validated source representation stored by this downloader instance
 */
public abstract class PluginDownLoader<T> {

  private T source;

  /**
   * Creates a new downloader instance.
   *
   * <p>Subclasses typically remain lightweight and are configured by calling {@link
   * #setSource(String)} before starting a download. This constructor performs no I/O and does not
   * validate any source; it only creates the object in its initial state.
   */
  protected PluginDownLoader() {}

  /**
   * Validates and stores the plugin source string for this downloader instance.
   *
   * <p>This method converts the raw {@code source} string into the implementation-specific typed
   * representation via {@link #checkSource(String)} and stores it for later retrieval through
   * {@link #getSource()}. It also returns the user-facing plugin name derived from the same input.
   * Callers should treat this method as a precondition for starting a download, unless the
   * implementation explicitly supports a different lifecycle.
   *
   * <p>This method is not required to be idempotent across different {@code source} values; calling
   * it multiple times overwrites the stored source for this instance.
   *
   * @param source Raw source string to validate (for example, a URI-like identifier or key)
   * @return A human-readable plugin name derived from the validated source string
   * @throws PluginNotFoundException If the source string cannot be validated or resolved
   */
  public String setSource(String source) throws PluginNotFoundException {
    this.source = checkSource(source);
    return getPluginName(source);
  }

  /**
   * Returns the validated source representation stored on this downloader instance.
   *
   * <p>The returned value is the result of the last successful call to {@link #setSource(String)}
   * (specifically, the value produced by {@link #checkSource(String)}). Callers should not assume
   * immutability; treat the returned object as implementation-owned unless documentation states
   * otherwise. If {@link #setSource(String)} has not been called yet, this method returns {@code
   * null}.
   *
   * @return The validated source representation for this instance, or {@code null} if unset
   */
  public T getSource() {
    return source;
  }

  abstract InputStream getInputStream(PluginProgress progress)
      throws IOException, PluginNotFoundException;

  abstract T checkSource(String source) throws PluginNotFoundException;

  abstract String getPluginName(String source) throws PluginNotFoundException;

  abstract String getSHA1sum() throws PluginNotFoundException;

  /** Cancel the load if possible */
  abstract void tryCancel();

  /**
   * Returns whether the plugin manager should avoid caching the downloaded bytes.
   *
   * <p>The default implementation returns {@code false}. Subclasses may override to prohibit
   * caching when the source is transient, user-specific, or otherwise not safe to persist. This
   * flag is advisory; callers are responsible for enforcing any caching policy.
   *
   * @return {@code true} if caching should be avoided for this download, otherwise {@code false}
   */
  public boolean isCachingProhibited() {
    return false;
  }

  /**
   * Returns whether this downloader represents an official plugin source.
   *
   * <p>The default implementation returns {@code false}. Subclasses may override to allow the
   * plugin manager or user interface to distinguish between official and non-official sources. The
   * specific meaning of "official" is defined by the caller and the concrete implementation.
   *
   * @return {@code true} if this loader considers the source official, otherwise {@code false}
   */
  public boolean isOfficialPluginLoader() {
    return false;
  }

  /**
   * Returns whether the download originates from the Freenet network.
   *
   * <p>The default implementation returns {@code false}. Subclasses may override to indicate that
   * the bytes are fetched via Freenet-specific retrieval rather than from a local file or an
   * external transport. Callers may use this to adjust progress reporting and/or UI wording.
   *
   * @return {@code true} if this loader fetches from Freenet, otherwise {@code false}
   */
  public boolean isLoadingFromFreenet() {
    return false;
  }

  /**
   * Returns a {@link PluginDownLoader} that can be used to restart a plugin download.
   *
   * <p>The default implementation returns {@code this}. Implementations that keep transient,
   * single-use state (for example, open streams, temporary files, or partially-consumed progress)
   * should override this method to return a fresh downloader instance suitable for re-running the
   * download. Callers should ensure the returned downloader is configured consistently (for
   * example, by calling {@link #setSource(String)} again when required by the implementation).
   *
   * @return A plugin downloader suitable for restarting the download
   */
  public PluginDownLoader<T> getRetryDownloader() {
    return this;
  }
}
