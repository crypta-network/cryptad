package network.crypta.runtime.spi;

/**
 * Captures the detached read-only runtime state needed to render the welcome page.
 *
 * <p>The welcome page still owns its HTML structure, bookmark rendering, and action routing. This
 * record exists so the GET path can make a small number of configuration-backed UI decisions
 * without reading live daemon configuration directly. The value is immutable and intentionally
 * narrow: it models only the state that this migration step needs, rather than a broader
 * representation of the entire home page.
 *
 * <p>Callers usually get one snapshot near the start of request handling and reuse it for the rest
 * of that render. That keeps page assembly deterministic for a single request even if the
 * underlying configuration changes later.
 *
 * @param fetchKeyBoxAboveBookmarks whether the fetch-a-key box should render before the bookmarks
 *     section for the current request render
 */
public record WelcomePageSnapshot(boolean fetchKeyBoxAboveBookmarks) {}
