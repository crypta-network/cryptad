/**
 * Adapter-owned bookmark runtime bridges for the HTTP shell.
 *
 * <p>This package contains the concrete bookmark-side adapters that keep the legacy HTTP bookmark
 * subsystem talking to daemon services without letting bookmark code depend directly on {@code
 * NodeClientCore}. The classes here translate bookmark operations such as locating bookmark files,
 * subscribing to USK updates, prefetching refreshed editions, and scheduling delayed store work
 * onto the existing node services that already implement those behaviors.
 *
 * <p>That ownership split matters because bookmark management still belongs to the HTTP adapter
 * layer, while the runtime-owned seams stay intentionally narrow and compile-neutral. Code outside
 * the adapter boundary should depend on the bookmark runtime interfaces under {@code
 * network.crypta.clients.http.bookmark} rather than these concrete bridge implementations. Keeping
 * the bridge localized here preserves the existing bookmark bootstrap path while making the
 * remaining daemon coupling explicit.
 */
package network.crypta.clients.http.bridge.bookmark;
