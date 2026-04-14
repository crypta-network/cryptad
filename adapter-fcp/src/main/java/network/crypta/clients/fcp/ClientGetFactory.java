package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Builds fully configured {@link ClientGet} instances from FCP inputs.
 *
 * <p>The factory performs the deterministic wiring for GET requests: it validates identifiers,
 * assembles an appropriate detached fetch configuration, plans return handling, and packages
 * everything into a {@link ClientGetSetup}. Callers use the resulting request object for
 * registration and execution; the factory does not start or enqueue the request itself. Because it
 * is stateless and uses only local variables, the class is thread-safe and can be called
 * concurrently.
 *
 * <p>The factory is intentionally conservative about side effects: it only logs ignored parameters
 * (such as a legacy charset hint) and throws explicit exceptions for identifier collisions or
 * invalid return targets. This makes it suitable for both connection-scoped requests and global
 * queue requests where persistence and DDA checks are required.
 *
 * <ul>
 *   <li><strong>Validation</strong>: checks identifier uniqueness in the appropriate scope.
 *   <li><strong>Context setup</strong>: clones and adjusts a persistent fetch configuration.
 *   <li><strong>Return planning</strong>: resolves disk/bucket targets and metadata buckets.
 * </ul>
 *
 * @see ClientGet
 * @see ClientGetMessage
 * @see ClientGetReturnPlanner
 */
final class ClientGetFactory {
  /** Logger for configuration-related diagnostics during request construction. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetFactory.class);

  /** Prevents instantiation; this class exposes only static factory helpers. */
  private ClientGetFactory() {}

  /**
   * Creates a persistent, global-queue {@link ClientGet} from a validated configuration.
   *
   * <p>The method derives persistent fetch defaults from the runtime bridge, applies the
   * configuration's limits and flags, and plans the return path according to {@link
   * ClientGet.ReturnType}. It then constructs a {@link ClientGet} instance without starting it. The
   * returned request is ready to be registered with a persistent client and subsequently started.
   *
   * <p>This factory is strict about identifier collisions and output policy. It will throw if the
   * identifier is already in use or if disk output is disallowed by the configured DDA policy.
   *
   * @param globalClient persistent client used for global-queue ownership and id checks.
   * @param uri target {@link FreenetURI} describing the key to fetch; must be non-null.
   * @param requestConfig immutable configuration with limits, flags, and return preferences.
   * @param fetchRuntimeSupport fetch runtime support providing fetch defaults, planners, and bucket
   *     allocation.
   * @return configured {@link ClientGet} instance ready for registration and start.
   * @throws IdentifierCollisionException if the identifier is already registered globally.
   * @throws NotAllowedException if disk output violates policy or DDA restrictions.
   * @throws IOException if bucket or file initialization fails during setup.
   */
  static ClientGet fromGlobal(
      PersistentRequestClient globalClient,
      FreenetURI uri,
      ClientGet.GlobalRequestConfig requestConfig,
      FcpFetchRuntimeSupport fetchRuntimeSupport)
      throws IdentifierCollisionException, NotAllowedException, IOException {
    return fromGlobal(globalClient, uri, requestConfig.toInternalConfig(), fetchRuntimeSupport);
  }

  /**
   * Creates a persistent, global-queue {@link ClientGet} from the package-local configuration
   * record used by the refactored GET path.
   *
   * <p>This overload keeps the internal seam narrow while the public {@link
   * ClientGet.GlobalRequestConfig} compatibility alias remains available for external callers.
   *
   * @param globalClient persistent client used for global-queue ownership and id checks.
   * @param uri target {@link FreenetURI} describing the key to fetch; must be non-null.
   * @param requestConfig immutable configuration with limits, flags, and return preferences.
   * @param fetchRuntimeSupport fetch runtime support providing fetch defaults, planners, and bucket
   *     allocation.
   * @return configured {@link ClientGet} instance ready for registration and start.
   * @throws IdentifierCollisionException if the identifier is already registered globally.
   * @throws NotAllowedException if disk output violates policy or DDA restrictions.
   * @throws IOException if bucket or file initialization fails during setup.
   */
  static ClientGet fromGlobal(
      PersistentRequestClient globalClient,
      FreenetURI uri,
      ClientGetGlobalRequestConfig requestConfig,
      FcpFetchRuntimeSupport fetchRuntimeSupport)
      throws IdentifierCollisionException, NotAllowedException, IOException {
    ensureGlobalIdentifierAvailable(globalClient, requestConfig.identifier());
    ClientGetFetchConfig fetchConfig =
        buildFetchConfigForGlobal(fetchRuntimeSupport, requestConfig);
    if (requestConfig.charset() != null && LOG.isDebugEnabled()) {
      LOG.debug(
          "Charset parameter is ignored for ClientGet global queue requests: {}",
          requestConfig.charset());
    }
    ClientGetReturnPlanner.ReturnSetup returnSetup =
        ClientGetGetterFactory.planReturnForGlobal(
            requestConfig.identifier(),
            fetchConfig,
            requestConfig.returnType(),
            requestConfig.returnFilename(),
            requestConfig.filterData(),
            fetchRuntimeSupport.transferAccess());
    ClientRequestParams params =
        new ClientRequestParams(
            uri,
            requestConfig.identifier(),
            requestConfig.verbosity(),
            requestConfig.prioClass(),
            (requestConfig.persistRebootOnly()
                ? ClientRequest.Persistence.REBOOT
                : ClientRequest.Persistence.FOREVER),
            requestConfig.realTimeFlag(),
            null,
            true);
    ClientGetSetup requestSetup =
        new ClientGetSetup(
            fetchConfig,
            returnSetup,
            requestConfig.returnType(),
            requestConfig.binaryBlob(),
            null,
            fetchRuntimeSupport);
    return new ClientGet(params, globalClient, requestSetup);
  }

  /**
   * Creates a connection-scoped or global {@link ClientGet} from a parsed FCP message.
   *
   * <p>The method constructs request parameters from the message, validates identifier scope, and
   * applies message-specific fetch context overrides. It also resolves any requested return targets
   * and optional initial metadata buckets. The request is returned in a configured but not started
   * state, so the caller can register it and schedule execution explicitly.
   *
   * <p>Any bucket creation failures are wrapped into a {@link MessageInvalidException} with an
   * internal-error code to match FCP error reporting expectations.
   *
   * @param handler connection handler supplying scope checks and DDA enforcement hooks.
   * @param message parsed FCP GET message containing identifiers, flags, and limits.
   * @param fetchRuntimeSupport fetch runtime support providing contexts, planners, and buckets.
   * @return configured {@link ClientGet} instance ready for registration and start.
   * @throws IdentifierCollisionException if the identifier is already used in scope.
   * @throws MessageInvalidException if validation fails or bucket setup throws I/O errors.
   */
  static ClientGet fromMessage(
      FCPConnectionHandler handler,
      ClientGetMessage message,
      FcpFetchRuntimeSupport fetchRuntimeSupport)
      throws IdentifierCollisionException, MessageInvalidException {
    ClientRequestParams params =
        new ClientRequestParams(
            message.uri,
            message.identifier,
            message.verbosity,
            message.priorityClass,
            message.persistence,
            message.realTimeFlag,
            message.clientToken,
            message.global);
    if (message.persistence == ClientRequest.Persistence.CONNECTION) {
      ensureConnectionIdentifierAvailable(handler, message.identifier);
    }
    ClientGetFetchConfig fetchConfig = buildFetchConfigForMessage(fetchRuntimeSupport, message);
    ClientGetReturnPlanner.ReturnSetup returnSetup =
        ClientGetGetterFactory.planReturnForMessage(
            message.identifier,
            message.global,
            fetchConfig,
            message,
            fetchRuntimeSupport.transferAccess(),
            handler);
    Bucket initialMetadata = message.getInitialMetadata();
    try {
      ClientGetSetup requestSetup =
          new ClientGetSetup(
              fetchConfig,
              returnSetup,
              message.returnType,
              message.binaryBlob,
              initialMetadata,
              fetchRuntimeSupport);
      return new ClientGet(params, handler, requestSetup);
    } catch (IOException e) {
      throw bucketCreationFailure(e, message.identifier, message.global);
    }
  }

  /**
   * Ensures the global identifier is not already registered on the persistent client.
   *
   * <p>This method performs a lightweight lookup against the persistent client map and throws when
   * the identifier is already reserved. When the client is {@code null}, the check is skipped to
   * allow callers to validate other aspects without requiring a backing queue.
   *
   * @param client persistent client whose identifier map is checked for collisions.
   * @param identifier candidate identifier that must be unique in the global queue.
   * @throws IdentifierCollisionException if the identifier is already present.
   */
  private static void ensureGlobalIdentifierAvailable(
      PersistentRequestClient client, String identifier) throws IdentifierCollisionException {
    if (client != null && client.getRequest(identifier) != null) {
      throw new IdentifierCollisionException();
    }
  }

  /**
   * Ensures the connection-scoped identifier is not already in use by the handler.
   *
   * <p>This check protects per-connection namespaces, so multiple requests do not share an
   * identifier. If the handler is {@code null}, the check is skipped to allow callers to validate
   * other parameters first.
   *
   * @param handler connection handler tracking identifiers for the active session.
   * @param identifier candidate identifier that must be unique for the connection.
   * @throws IdentifierCollisionException if the identifier already exists in scope.
   */
  private static void ensureConnectionIdentifierAvailable(
      FCPConnectionHandler handler, String identifier) throws IdentifierCollisionException {
    if (handler != null && handler.requestsByIdentifier.containsKey(identifier)) {
      throw new IdentifierCollisionException();
    }
  }

  /**
   * Builds detached fetch configuration for global-queue requests using persistent defaults.
   *
   * <p>The context is cloned from the node core's persistent template and then adjusted with the
   * configuration's limits, datastore flags, and filtering preferences. The returned context is
   * mutable and owned by the caller; further modifications affect only the request being built.
   *
   * @param fetchRuntimeSupport fetch runtime support providing the default persistent fetch
   *     context.
   * @param requestConfig configuration containing datastore flags and retry limits.
   * @return configured detached fetch configuration tailored for this request.
   */
  private static ClientGetFetchConfig buildFetchConfigForGlobal(
      FcpFetchRuntimeSupport fetchRuntimeSupport, ClientGetGlobalRequestConfig requestConfig) {
    ClientGetFetchConfig fetchConfig = fetchRuntimeSupport.defaultPersistentFetchConfig();
    fetchConfig.setLocalRequestOnly(requestConfig.dsOnly());
    fetchConfig.setIgnoreStore(requestConfig.ignoreDS());
    fetchConfig.setMaxNonSplitfileRetries(requestConfig.maxNonSplitfileRetries());
    fetchConfig.setMaxSplitfileBlockRetries(requestConfig.maxSplitfileRetries());
    fetchConfig.setFilterData(requestConfig.filterData());
    fetchConfig.setMaxOutputLength(requestConfig.maxOutputLength());
    fetchConfig.setMaxTempLength(requestConfig.maxOutputLength());
    fetchConfig.setCanWriteClientCache(requestConfig.writeToClientCache());
    return fetchConfig;
  }

  /**
   * Builds detached fetch configuration for message-driven requests with per-message overrides.
   *
   * <p>The context starts from the persistent defaults and is then updated with message-specific
   * retry limits, size limits, allowed MIME types, and USK date hint behavior. The returned context
   * is owned by the caller and can be further adjusted before the request starts.
   *
   * @param fetchRuntimeSupport fetch runtime support providing the default persistent fetch
   *     context.
   * @param message the parsed message supplying overrides and allowed MIME type hints.
   * @return configured detached fetch configuration tailored for the message.
   */
  private static ClientGetFetchConfig buildFetchConfigForMessage(
      FcpFetchRuntimeSupport fetchRuntimeSupport, ClientGetMessage message) {
    ClientGetFetchConfig fetchConfig = fetchRuntimeSupport.defaultPersistentFetchConfig();
    fetchConfig.setLocalRequestOnly(message.dsOnly);
    fetchConfig.setIgnoreStore(message.ignoreDS);
    fetchConfig.setMaxNonSplitfileRetries(message.maxRetries);
    fetchConfig.setMaxSplitfileBlockRetries(message.maxRetries);
    fetchConfig.setMaxOutputLength(message.maxSize);
    fetchConfig.setMaxTempLength(message.maxTempSize);
    fetchConfig.setCanWriteClientCache(message.shouldWriteToClientCache());
    fetchConfig.setFilterData(message.filterData);
    fetchConfig.setIgnoreUSKDatehints(message.ignoreUSKDatehints);
    ClientGetGetterFactory.applyAllowedMimeTypes(fetchConfig, message.allowedMIMETypes);
    return fetchConfig;
  }

  /**
   * Wraps bucket creation failures in a protocol error suitable for FCP clients.
   *
   * <p>The returned {@link MessageInvalidException} preserves the original cause and uses the
   * standard internal-error code so the caller can relay a consistent error message upstream.
   *
   * @param e underlying I/O failure that prevented temporary bucket creation.
   * @param identifier request identifier associated with the failing request.
   * @param global true when the request targets the global queue.
   * @return FCP error wrapper that retains the original cause and identifier.
   */
  private static MessageInvalidException bucketCreationFailure(
      IOException e, String identifier, boolean global) {
    MessageInvalidException mie =
        new MessageInvalidException(
            ProtocolErrorMessage.INTERNAL_ERROR,
            "Cannot create bucket for temporary storage (out of disk space?): " + e,
            identifier,
            global);
    mie.initCause(e);
    return mie;
  }
}
