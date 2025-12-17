package network.crypta.pluginmanager;

/**
 * Signals that a plugin load request attempted to load a plugin whose main class is already loaded.
 *
 * <p>This exception is used by the plugin management subsystem as a lightweight, type-safe signal
 * for duplicate-load conditions. It is typically thrown during a call path that resolves a plugin's
 * main class name and compares it against the set of already-registered plugins (for example, from
 * within {@code PluginManager}). The class intentionally carries no additional structured state;
 * callers that need more context should consult the surrounding plugin manager state (for example,
 * the requested main class name and the currently loaded plugins) when constructing user-facing
 * messages.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Indicates a uniqueness invariant: at most one loaded plugin per main class name.
 *   <li>Conveys only the duplicate-load condition, not the plugin's internal lifecycle state.
 *   <li>Retrying the same request is expected to fail until the loaded set changes.
 * </ul>
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public class PluginAlreadyLoaded extends Exception {

  /**
   * Creates an instance indicating that the requested plugin is already loaded.
   *
   * <p>This constructor produces an exception without a detail message or explicit cause. It is
   * appropriate when the duplicate-load condition itself is sufficient to guide control flow, and
   * any user-facing explanation is generated at a higher layer (for example, by reporting the
   * requested main class name and the currently loaded plugins). The resulting instance still
   * records a stack trace, which can aid debugging and diagnostics.
   */
  public PluginAlreadyLoaded() {
    /* Intentionally empty: this exception carries no message or cause. */
  }
}
