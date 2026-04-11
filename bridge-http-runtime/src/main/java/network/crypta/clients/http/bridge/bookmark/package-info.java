/**
 * Concrete bookmark runtime bridges for the legacy HTTP shell.
 *
 * <p>This package now lives in {@code :bridge-http-runtime}. The classes here keep the legacy HTTP
 * bookmark subsystem talking to daemon services without letting bookmark code depend directly on
 * {@code NodeClientCore}. They translate bookmark operations such as locating bookmark files,
 * subscribing to USK updates, prefetching refreshed editions, and scheduling delayed store work
 * onto the existing node services that already implement those behaviors.
 *
 * <p>That ownership split matters because bookmark management still belongs to the legacy HTTP
 * shell, while the concrete runtime-binding adapters now live in the separate bridge leaf. Code
 * outside the bridge should depend on the bookmark runtime interfaces under {@code
 * network.crypta.clients.http.bookmark} rather than these implementations. Keeping the bridge
 * localized here preserves the existing bookmark bootstrap path while making the remaining daemon
 * coupling explicit.
 */
package network.crypta.clients.http.bridge.bookmark;
