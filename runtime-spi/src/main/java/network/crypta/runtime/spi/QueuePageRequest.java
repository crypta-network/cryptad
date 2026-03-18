package network.crypta.runtime.spi;

/**
 * Immutable request parameters for one detached legacy queue-page render.
 *
 * <p>The legacy queue UI is still page-oriented rather than domain-oriented, so callers pass only
 * the small set of flags that influence how the read-only page is assembled: which queue side is
 * being rendered, whether advanced mode is enabled, and which optional sort is active.
 *
 * <p>This record deliberately omits HTTP-owned context such as request objects, access-control
 * state, and form-password values. It also omits daemon-owned queue model types. That keeps the
 * runtime SPI stable while the queue page is migrated incrementally from direct toadlet rendering
 * toward detached runtime-backed snapshots.
 *
 * @param uploads whether the upload queue should be rendered instead of downloads
 * @param advancedMode whether advanced-only sections and columns should be included
 * @param sortBy requested sort key, or {@code null} to keep default ordering
 * @param reversed whether the selected sort should be inverted
 */
public record QueuePageRequest(
    boolean uploads, boolean advancedMode, String sortBy, boolean reversed) {}
