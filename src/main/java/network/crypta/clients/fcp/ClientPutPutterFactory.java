package network.crypta.clients.fcp;

import network.crypta.client.async.ClientPutter;
import network.crypta.client.async.ClientPutterOptions;
import network.crypta.client.async.ClientPutterRequest;

/**
 * Creates {@link ClientPutter} instances for single-file insert requests.
 *
 * <p>This factory centralizes the final assembly of {@link ClientPutter} objects after higher-level
 * request logic has already prepared a {@link ClientPutterRequest} and {@link ClientPutterOptions}.
 * Keeping the construction in one place makes it easier to enforce consistent wiring when request
 * constructors evolve, and it isolates the putter instantiation details from the surrounding FCP
 * request classes.
 *
 * <p>The factory performs no validation beyond delegating to the {@link ClientPutter} constructor;
 * callers are expected to pass fully configured, non-null request and options objects. The method
 * is deterministic and side-effect free, so it is safe to call from any thread that is building a
 * request.
 *
 * <ul>
 *   <li>Constructs a {@link ClientPutter} from prepared request and option objects.
 *   <li>Preserves all wiring performed by the caller without additional mutation.
 * </ul>
 *
 * @see ClientPutter
 * @see ClientPutterRequest
 * @see ClientPutterOptions
 */
final class ClientPutPutterFactory {
  /** Prevents instantiation; this class provides a single static factory method. */
  private ClientPutPutterFactory() {}

  /**
   * Creates a new {@link ClientPutter} using the supplied request and options.
   *
   * <p>The method simply delegates to the {@link ClientPutter} constructor and returns the result.
   * It does not mutate the request or options and performs no I/O. Callers should ensure that the
   * request object already contains the target URI, bucket, metadata, and any persistence flags
   * required by the insert pipeline.
   *
   * @param request prepared {@link ClientPutterRequest} containing callback, bucket, and metadata;
   *     must not be {@code null}.
   * @param options prepared {@link ClientPutterOptions} describing filename, binary-blob state, and
   *     metadata thresholds; must not be {@code null}.
   * @return a new {@link ClientPutter} instance wired to the given request and options.
   */
  static ClientPutter create(ClientPutterRequest request, ClientPutterOptions options) {
    return new ClientPutter(request, options);
  }
}
