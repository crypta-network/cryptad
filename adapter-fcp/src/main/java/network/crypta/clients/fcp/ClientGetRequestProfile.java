package network.crypta.clients.fcp;

import java.io.File;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.support.api.Bucket;

/**
 * Immutable request-owned setup profile for a {@link ClientGet}.
 *
 * <p>This value object gathers the long-lived configuration chosen while a GET request is
 * assembled: the detached fetch configuration, the selected return strategy, optional target-file
 * details, and the narrow runtime seam needed to create or resume the underlying getter. Grouping
 * those values behind one profile keeps {@link ClientGet} itself smaller and reduces the number of
 * direct type-level dependencies that the request needs to carry.
 *
 * <p>The profile is intentionally shallow and stable. Callers replace it wholesale when they need a
 * modified variant rather than mutating fields in place, which makes restart and persistence code
 * easier to reason about. The only deliberately transient member is {@link #runtimeFetchSupport()},
 * because live runtime bindings are reconstructed when a request is resumed rather than serialized
 * into persistent request state.
 */
final class ClientGetRequestProfile implements Serializable {
  /** Stable serialization version for detached request profiles. */
  @Serial private static final long serialVersionUID = 1L;

  /** Detached fetch configuration selected for this request. */
  private final ClientGetFetchConfig fetchConfig;

  /** Return mode that controls whether the GET writes to disk, memory, or another sink. */
  private final ClientGet.ReturnType returnType;

  /** Destination file chosen for disk-return modes, or {@code null} when no file target exists. */
  private final File targetFile;

  /** Whether the request expects binary-blob handling instead of normal metadata processing. */
  private final boolean binaryBlob;

  /** Optional extension hint that later getter setup uses for output validation. */
  private final String extensionCheck;

  /** Metadata bucket staged before the live getter is created if one is available. */
  @SuppressWarnings("java:S1948")
  private final Bucket initialMetadata;

  /** Live runtime seam used to create or resume the getter after construction or replay. */
  private final transient FcpFetchRuntimeSupport runtimeFetchSupport;

  /**
   * Builds a fully populated immutable profile from its constituent request-owned values.
   *
   * @param fetchConfig detached fetch configuration selected for the request
   * @param returnType return mode that describes the destination strategy
   * @param targetFile target file for disk-return modes, or {@code null} when not applicable
   * @param binaryBlob whether the request is operating in binary-blob mode
   * @param extensionCheck optional extension-check hint, or {@code null} when none is configured
   * @param initialMetadata optional staged metadata bucket, or {@code null} when none is present
   * @param runtimeFetchSupport live runtime seam for getter creation and replay, or {@code null}
   *     for placeholder profiles
   */
  private ClientGetRequestProfile(
      ClientGetFetchConfig fetchConfig,
      ClientGet.ReturnType returnType,
      File targetFile,
      boolean binaryBlob,
      String extensionCheck,
      Bucket initialMetadata,
      FcpFetchRuntimeSupport runtimeFetchSupport) {
    this.fetchConfig = fetchConfig;
    this.returnType = returnType;
    this.targetFile = targetFile;
    this.binaryBlob = binaryBlob;
    this.extensionCheck = extensionCheck;
    this.initialMetadata = initialMetadata;
    this.runtimeFetchSupport = runtimeFetchSupport;
  }

  /**
   * Creates a profile from the fully validated setup computed for a newly constructed request.
   *
   * <p>Use this factory once the GET parser and return planner have already agreed on the detached
   * fetch configuration and the destination behavior. The resulting profile retains only the stable
   * values that later lifecycle helpers need, not the broader setup scaffolding used to derive
   * them.
   *
   * @param setup validated setup bundle produced while assembling a fresh GET request
   * @return immutable profile containing the request-owned setup values from {@code setup}
   */
  static ClientGetRequestProfile fromSetup(ClientGetSetup setup) {
    ClientGetReturnPlanner.ReturnSetup returnSetup = setup.returnSetup();
    return new ClientGetRequestProfile(
        setup.fetchConfig(),
        setup.returnType(),
        returnSetup.targetFile(),
        setup.binaryBlob(),
        returnSetup.extension(),
        setup.initialMetadata(),
        setup.fetchRuntimeSupport());
  }

  /**
   * Recreates a profile from persistence-layer restore data plus a fresh runtime binding.
   *
   * <p>Persistent replay stores the detached request parameters but deliberately omits the live
   * runtime seam. This factory recombines the stored values with the current {@link
   * FcpFetchRuntimeSupport} instance so resumed requests can recreate getters without widening the
   * serialized state.
   *
   * @param restoreData detached restore data read from persistence
   * @param fetchRuntimeSupport live runtime seam that resumed requests should use
   * @return immutable profile suitable for request resume and replay code paths
   */
  static ClientGetRequestProfile fromRestoreData(
      ClientGetPersistenceCodec.BasicRestoreData restoreData,
      FcpFetchRuntimeSupport fetchRuntimeSupport) {
    return new ClientGetRequestProfile(
        restoreData.fetchConfig(),
        restoreData.returnType(),
        restoreData.targetFile(),
        restoreData.binaryBlob(),
        restoreData.extensionCheck(),
        restoreData.initialMetadata(),
        fetchRuntimeSupport);
  }

  /**
   * Recreates a profile from the field layout used before the request-profile refactor.
   *
   * <p>Older Java-serialized {@link ClientGet} instances stored these values directly on the
   * request rather than grouping them in this value object. The runtime seam was transient even in
   * the legacy layout, so resumed requests still need to resolve it separately after
   * deserialization.
   *
   * @param fetchConfig detached fetch configuration stored on the legacy request
   * @param returnType return mode stored on the legacy request
   * @param targetFile legacy disk target file, or {@code null} when none was configured
   * @param binaryBlob whether the legacy request used binary-blob handling
   * @param extensionCheck legacy extension-check hint, or {@code null} when absent
   * @param initialMetadata legacy staged metadata bucket, or {@code null} when absent
   * @return immutable profile reconstructed from the legacy serialized field set
   */
  static ClientGetRequestProfile fromLegacySerializedFields(
      ClientGetFetchConfig fetchConfig,
      ClientGet.ReturnType returnType,
      File targetFile,
      boolean binaryBlob,
      String extensionCheck,
      Bucket initialMetadata) {
    return new ClientGetRequestProfile(
        fetchConfig, returnType, targetFile, binaryBlob, extensionCheck, initialMetadata, null);
  }

  /**
   * Returns an inert placeholder profile for serialization-only constructors and test scaffolding.
   *
   * <p>The placeholder keeps every member null or false, which allows callers to instantiate {@link
   * ClientGet} before real state is injected. Normal request construction should prefer {@link
   * #fromSetup(ClientGetSetup)} or {@link
   * #fromRestoreData(ClientGetPersistenceCodec.BasicRestoreData, FcpFetchRuntimeSupport)}.
   *
   * @return empty profile with no fetch or return configuration attached
   */
  static ClientGetRequestProfile empty() {
    return new ClientGetRequestProfile(null, null, null, false, null, null, null);
  }

  /**
   * Returns the detached fetch configuration stored in this profile.
   *
   * @return detached fetch configuration, or {@code null} for placeholder profiles
   */
  ClientGetFetchConfig fetchConfig() {
    return fetchConfig;
  }

  /**
   * Returns the configured return type for this request profile.
   *
   * @return return mode selected for the request, or {@code null} for placeholder profiles
   */
  ClientGet.ReturnType returnType() {
    return returnType;
  }

  /**
   * Returns the configured target file when the request writes to disk.
   *
   * @return target file, or {@code null} when no file-return mode is configured
   */
  File targetFile() {
    return targetFile;
  }

  /**
   * Returns whether this profile enables binary-blob mode.
   *
   * @return {@code true} when binary-blob handling is enabled; otherwise {@code false}
   */
  boolean binaryBlob() {
    return binaryBlob;
  }

  /**
   * Returns the stored extension-check hint.
   *
   * @return extension-check string, or {@code null} when no hint is configured
   */
  String extensionCheck() {
    return extensionCheck;
  }

  /**
   * Returns the staged metadata bucket stored in this profile.
   *
   * @return initial metadata bucket, or {@code null} when none is attached
   */
  Bucket initialMetadata() {
    return initialMetadata;
  }

  /**
   * Returns the live runtime seam associated with this profile.
   *
   * @return runtime fetch support, or {@code null} when the profile is a placeholder snapshot
   */
  FcpFetchRuntimeSupport runtimeFetchSupport() {
    return runtimeFetchSupport;
  }

  /**
   * Returns a copy of this profile with a replacement fetch configuration.
   *
   * @param value replacement detached fetch configuration
   * @return new profile that differs only in its fetch configuration
   */
  ClientGetRequestProfile withFetchConfig(ClientGetFetchConfig value) {
    return new ClientGetRequestProfile(
        value,
        returnType,
        targetFile,
        binaryBlob,
        extensionCheck,
        initialMetadata,
        runtimeFetchSupport);
  }

  /**
   * Returns a copy of this profile with a replacement return type.
   *
   * @param value replacement return strategy for the request
   * @return new profile that differs only in its return type
   */
  ClientGetRequestProfile withReturnType(ClientGet.ReturnType value) {
    return new ClientGetRequestProfile(
        fetchConfig,
        value,
        targetFile,
        binaryBlob,
        extensionCheck,
        initialMetadata,
        runtimeFetchSupport);
  }

  /**
   * Returns a copy of this profile with a replacement target file.
   *
   * @param value replacement destination file, or {@code null} when no disk target is configured
   * @return new profile that differs only in its target file
   */
  ClientGetRequestProfile withTargetFile(File value) {
    return new ClientGetRequestProfile(
        fetchConfig,
        returnType,
        value,
        binaryBlob,
        extensionCheck,
        initialMetadata,
        runtimeFetchSupport);
  }

  /**
   * Returns a copy of this profile with an updated binary-blob flag.
   *
   * @param value replacement binary-blob mode flag
   * @return new profile that differs only in its binary-blob flag
   */
  ClientGetRequestProfile withBinaryBlob(boolean value) {
    return new ClientGetRequestProfile(
        fetchConfig,
        returnType,
        targetFile,
        value,
        extensionCheck,
        initialMetadata,
        runtimeFetchSupport);
  }

  /**
   * Returns a copy of this profile with a replacement extension-check hint.
   *
   * @param value replacement extension check string, or {@code null} when none is required
   * @return new profile that differs only in its extension-check hint
   */
  @SuppressWarnings("unused")
  ClientGetRequestProfile withExtensionCheck(String value) {
    return new ClientGetRequestProfile(
        fetchConfig,
        returnType,
        targetFile,
        binaryBlob,
        value,
        initialMetadata,
        runtimeFetchSupport);
  }

  /**
   * Returns a copy of this profile with replacement initial metadata.
   *
   * @param value replacement metadata bucket, or {@code null} when no metadata bucket is staged
   * @return new profile that differs only in its initial metadata bucket
   */
  @SuppressWarnings("unused")
  ClientGetRequestProfile withInitialMetadata(Bucket value) {
    return new ClientGetRequestProfile(
        fetchConfig,
        returnType,
        targetFile,
        binaryBlob,
        extensionCheck,
        value,
        runtimeFetchSupport);
  }

  /**
   * Returns a copy of this profile with a replacement runtime fetch seam.
   *
   * <p>This is primarily used by resume and replay code that needs to reattach a freshly resolved
   * runtime binding after deserialization.
   *
   * @param value replacement live fetch runtime support
   * @return new profile that differs only in its runtime fetch seam
   */
  ClientGetRequestProfile withRuntimeFetchSupport(FcpFetchRuntimeSupport value) {
    return new ClientGetRequestProfile(
        fetchConfig, returnType, targetFile, binaryBlob, extensionCheck, initialMetadata, value);
  }
}
