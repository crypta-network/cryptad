package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.support.api.Bucket;

/**
 * Builds request-scoped {@link ClientGetExecution} handles from adapter-owned GET state.
 *
 * <p>This helper exists to keep {@link ClientGet} focused on request lifecycle orchestration
 * instead of also owning the boilerplate that converts detached request data into a {@link
 * ClientGetExecutionSpec}. The adapter still decides which fetch configuration, return bucket, and
 * request flags should apply to the current attempt, but the actual bundling of those values into
 * the bridge-facing execution descriptor is centralized here. That keeps the runtime handoff easy
 * to audit and avoids scattering execution-assembly rules across constructors, persistence code,
 * and restart paths.
 *
 * <p>The class is intentionally stateless. Every call creates a fresh execution descriptor, passes
 * through the current request-owned values, and delegates construction of the live runtime fetcher
 * to {@link FcpFetchRuntimeSupport}. No caching occurs here, so callers always get a descriptor
 * that reflects the request's current detached state.
 */
final class ClientGetExecutionFactory {
  /** Prevents instantiation because this class only exposes static assembly helpers. */
  private ClientGetExecutionFactory() {}

  /**
   * Creates a live execution for one GET request attempt.
   *
   * <p>The method snapshots the request-owned values that matter for runtime execution and
   * persistence: target URI, scheduler priority, detached fetch configuration, optional return
   * bucket, Binary Blob mode, persistence class, initial metadata, and extension hint used by the
   * filtering path. It also creates a fresh {@link ClientGetEventHandling} bridge so the runtime
   * execution can continue reporting progress and terminal callbacks back into the owning request.
   *
   * <p>The returned execution is ready to be started or resumed by the surrounding request
   * lifecycle. This method does not itself start network activity; it only performs the
   * deterministic assembly step before control passes to the runtime support implementation.
   *
   * @param request owning request whose detached state drives execution assembly.
   * @param fetchRuntimeSupport runtime seam that turns the detached execution descriptor into a
   *     live runtime fetcher.
   * @param returnBucket return bucket selected for this attempt, or {@code null} when the request
   *     discards payload data or lets the runtime allocate Binary Blob storage.
   * @return the configured live execution handle for the current request attempt.
   * @throws IOException if the runtime support cannot allocate or initialize the execution handle.
   */
  static ClientGetExecution create(
      ClientGet request, FcpFetchRuntimeSupport fetchRuntimeSupport, Bucket returnBucket)
      throws IOException {
    ClientGetRequestProfile requestProfile = request.requestProfile();
    ClientGetExecutionSpec executionSpec =
        new ClientGetExecutionSpec(
            request,
            request.getURI(),
            request.getPriority(),
            requestProfile.fetchConfig(),
            returnBucket,
            requestProfile.returnType() == ClientGet.ReturnType.NONE,
            requestProfile.binaryBlob(),
            request.persistence == ClientRequest.Persistence.FOREVER,
            requestProfile.initialMetadata(),
            requestProfile.extensionCheck(),
            new ClientGetEventHandling(request));
    return fetchRuntimeSupport.createExecution(executionSpec);
  }
}
