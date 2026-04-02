package network.crypta.runtime.http;

/**
 * Runtime-owned marker seam for HTTP shell runtime support.
 *
 * <p>This interface exists to keep runtime/bootstrap code compile-neutral with respect to the
 * legacy HTTP adapter package. Production bridge implementations may also implement the legacy
 * adapter-side runtime-support interface when they still need to back the existing HTTP shell. When
 * the runtime support is paired with the current {@code SimpleToadletServer}-backed container
 * bridge, the same object must also implement the legacy adapter-side interface because the legacy
 * shell still invokes that older API internally. Custom bridge configurations must therefore pair a
 * runtime-support factory with a container factory that expects the same backing contract.
 *
 * <p>The seam is intentionally empty for this PR. It marks the runtime-owned support object that
 * higher-level code creates and passes into the matching {@code
 * HttpShellContainer.setRuntimeSupport(...)} hook without redesigning the legacy HTTP
 * runtime-support API yet.
 */
public interface HttpShellRuntimeSupport {}
