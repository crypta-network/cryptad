package network.crypta.runtime.updater;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.spi.CoreSupportLifecycleStatus;

/**
 * Validates, persists, and projects last-known-good Stable 1.0 lifecycle state.
 *
 * <p>The state machine accepts only a contiguous descriptor successor whose predecessor digest
 * matches the predecessor semantic digest. It also preserves the release inventory, immutable
 * publication identity, deadline clocks, terminal build revocations, and monotonic per-build
 * transition chain. Failed fetches or validations update a bounded warning code but never discard
 * an already accepted descriptor. Explicit compromise of the update key is different: it
 * invalidates both the in-memory descriptor and its persisted copy because neither remains a
 * trustworthy lifecycle authority.
 *
 * <p>This component does not call {@link RevocationChecker}, {@link NodeUpdateManager#blow(String,
 * boolean)}, update installation, telemetry, or any destructive node operation. Its only durable
 * effects are replacing one public-safe last-known-good descriptor file after all checks pass and
 * durably invalidating that file when its authenticating update key is explicitly compromised.
 */
final class CoreSupportLifecycleState {
  private static final Pattern RUNTIME_SOURCE_COMMIT = Pattern.compile("[0-9a-f]{7,40}");
  private static final String RUNNING_BUILD_NOT_IN_LIFECYCLE_INVENTORY_WARNING =
      "running_build_not_in_lifecycle_inventory";
  private static final String LIFECYCLE_TRUST_INVALIDATED_WARNING = "lifecycle_trust_invalidated";
  private static final long LEGACY_REVOCATION_STATE_SCHEMA_VERSION = 1;
  private static final long SINGLE_BINDING_REVOCATION_STATE_SCHEMA_VERSION = 2;
  private static final long REVOCATION_STATE_SCHEMA_VERSION = 3;
  private static final int MAX_REVOCATION_STATE_ENTRIES = 256;
  private static final String SCHEMA_VERSION_FIELD = "schemaVersion";
  private static final String BUILD_VERSION_FIELD = "buildVersion";
  private static final String REVOCATION_ACTIVATIONS_FIELD = "revocationActivations";
  private static final String RUNNING_REVOCATION_PROJECTION_FIELD = "runningRevocationProjection";
  private static final String SOURCE_DESCRIPTOR_DIGEST_FIELD = "sourceDescriptorDigest";
  private static final String TARGET_DESCRIPTOR_DIGEST_FIELD = "targetDescriptorDigest";
  private static final String UPDATE_KEY_IDENTITY_DIGEST_FIELD = "updateKeyIdentityDigest";
  private static final String UPDATE_KEY_SCOPE_FIELD = "updateKeyScope";
  private static final String UPDATE_KEY_DOC_NAME_FIELD = "updateKeyDocName";

  private final CoreSupportLifecycleParser parser;
  private final CoreSupportLifecycleStore store;
  private final Clock clock;
  private final int runningBuild;
  private final String runningSourceCommit;

  private CoreSupportLifecycleParser.TrustBinding trust;
  private CoreSupportLifecycleDescriptor descriptor;
  private Instant lastVerifiedAt;
  private String lastFailureCode;
  private boolean trustInvalidated;
  private Map<Integer, Instant> revocationActivationByBuild = Map.of();
  private RunningRevocationProjection runningRevocationProjection;

  /**
   * Creates state for one running build and attempts to load a matching persisted descriptor.
   *
   * @param store local exact-byte last-known-good descriptor persistence
   * @param parser strict descriptor parser
   * @param clock time source used only for verification and staleness projection
   * @param runningBuild current Cryptad integer build
   * @param runningSourceCommit build-time source commit, or a placeholder in development builds
   * @param trust current configured public update-key binding
   */
  CoreSupportLifecycleState(
      CoreSupportLifecycleStore store,
      CoreSupportLifecycleParser parser,
      Clock clock,
      int runningBuild,
      String runningSourceCommit,
      CoreSupportLifecycleParser.TrustBinding trust) {
    this.store = Objects.requireNonNull(store, "store");
    this.parser = Objects.requireNonNull(parser, "parser");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.runningBuild = runningBuild;
    this.runningSourceCommit = runningSourceCommit;
    this.trust = Objects.requireNonNull(trust, "trust");
    loadPersisted();
  }

  /**
   * Accepts and durably replaces state with one exact authenticated descriptor successor.
   *
   * @param bytes exact fetched descriptor bytes
   * @param fetchedEdition actual support-lifecycle USK edition
   * @throws IllegalArgumentException if descriptor or transition validation fails
   * @throws IOException if last-known-good persistence fails
   */
  synchronized void accept(byte[] bytes, long fetchedEdition) throws IOException {
    if (trustInvalidated) {
      throw new IllegalArgumentException("lifecycle update-key trust has been invalidated");
    }
    CoreSupportLifecycleDescriptor candidate = parser.parse(bytes, fetchedEdition, trust);
    validateRunningIdentity(candidate);
    validateSuccessor(descriptor, candidate);
    Map<Integer, Instant> candidateRevocationActivations =
        revocationActivationsForSuccessor(descriptor, candidate);
    RunningRevocationProjection candidateRunningRevocationProjection =
        runningRevocationProjectionForSuccessor(descriptor, candidate);
    Instant verifiedAt = clock.instant();
    store.save(
        bytes,
        verifiedAt,
        encodeRevocationState(
            candidateRevocationActivations, candidateRunningRevocationProjection));
    descriptor = candidate;
    revocationActivationByBuild = candidateRevocationActivations;
    runningRevocationProjection = candidateRunningRevocationProjection;
    lastVerifiedAt = verifiedAt;
    lastFailureCode = null;
  }

  /** Records one bounded failure code while retaining prior last-known-good state. */
  synchronized void recordFailure(String failureCode) {
    if (!trustInvalidated) {
      lastFailureCode = safeFailureCode(failureCode);
    }
  }

  /**
   * Switches to a newly configured public update-key scope and reloads only matching persisted
   * state. An explicit compromise latch is never cleared by changing configuration.
   *
   * @param nextTrust newly derived public support-lifecycle trust binding
   */
  synchronized void changeTrust(CoreSupportLifecycleParser.TrustBinding nextTrust) {
    trust = Objects.requireNonNull(nextTrust, "nextTrust");
    descriptor = null;
    revocationActivationByBuild = Map.of();
    runningRevocationProjection = null;
    lastVerifiedAt = null;
    lastFailureCode = null;
    loadPersisted();
  }

  /**
   * Invalidates all state authenticated by an update key that is known to be compromised.
   *
   * <p>Memory is cleared before persistence is attempted so an I/O failure cannot leave the running
   * process claiming known lifecycle state. The bounded failure code deliberately names lifecycle
   * trust, not a build lifecycle status; build-level {@code revoked} remains an authenticated
   * descriptor state and never invokes this path.
   *
   * @return {@code true} when durable invalidation is recorded, or {@code false} when it fails
   */
  synchronized boolean invalidateCompromisedUpdateKey() {
    trustInvalidated = true;
    descriptor = null;
    revocationActivationByBuild = Map.of();
    runningRevocationProjection = null;
    lastVerifiedAt = null;
    lastFailureCode = LIFECYCLE_TRUST_INVALIDATED_WARNING;
    try {
      store.invalidateTrust();
      return true;
    } catch (IOException | RuntimeException _) {
      lastFailureCode = "lifecycle_trust_invalidation_persistence_failed";
      return false;
    }
  }

  /**
   * Returns a public-safe local lifecycle snapshot at the current clock instant.
   *
   * @return detached snapshot that distinguishes unknown, stale, and every closed build status
   */
  synchronized CoreSupportLifecycleSnapshot snapshot() {
    CoreSupportLifecycleDescriptor currentDescriptor = descriptor;
    if (currentDescriptor == null) {
      return CoreSupportLifecycleSnapshot.unknown(
          runningBuild, List.of(lastFailureCode == null ? "lifecycle_unknown" : lastFailureCode));
    }
    Instant now = clock.instant();
    boolean effective = !now.isBefore(currentDescriptor.effectiveAt());
    boolean stale = !now.isBefore(currentDescriptor.staleAt());
    Map<Integer, CoreSupportLifecycleEntry> byBuild = currentDescriptor.entriesByBuild();
    CoreSupportLifecycleEntry running = byBuild.get(runningBuild);
    if (running == null) {
      return new CoreSupportLifecycleSnapshot(
          false,
          stale,
          CoreSupportLifecycleSnapshot.RunningBuild.unknown(runningBuild),
          recommendation(currentDescriptor, effective),
          verification(currentDescriptor),
          runningBuildMissingWarnings(effective));
    }
    return snapshotForRunningBuild(currentDescriptor, running, effective, stale);
  }

  private CoreSupportLifecycleSnapshot snapshotForRunningBuild(
      CoreSupportLifecycleDescriptor currentDescriptor,
      CoreSupportLifecycleEntry running,
      boolean effective,
      boolean stale) {
    boolean effectiveRevocation = isBuildRevoked(runningBuild);
    boolean runningStatusKnown = effective || effectiveRevocation;
    return new CoreSupportLifecycleSnapshot(
        runningStatusKnown,
        stale,
        runningBuildSnapshot(running, effective, effectiveRevocation),
        recommendation(currentDescriptor, effective),
        verification(currentDescriptor),
        snapshotWarnings(running.lifecycleStatus(), effective, stale, effectiveRevocation));
  }

  private List<String> snapshotWarnings(
      CoreSupportLifecycleStatus status,
      boolean effective,
      boolean stale,
      boolean effectiveRevocation) {
    ArrayList<String> warningCodes = new ArrayList<>();
    if (!effective) {
      warningCodes.add("lifecycle_descriptor_not_effective");
    }
    if (stale) {
      warningCodes.add("lifecycle_descriptor_stale");
    }
    if (effective) {
      addStatusWarning(warningCodes, status);
    } else if (effectiveRevocation) {
      warningCodes.add("build_revoked");
    }
    if (lastFailureCode != null) {
      warningCodes.add(lastFailureCode);
    }
    return List.copyOf(warningCodes);
  }

  private CoreSupportLifecycleSnapshot.RunningBuild runningBuildSnapshot(
      CoreSupportLifecycleEntry running, boolean effective, boolean effectiveRevocation) {
    if (effective) {
      return activeRunningBuildSnapshot(running);
    }
    if (effectiveRevocation) {
      return effectiveRevocationSnapshot(running);
    }
    return CoreSupportLifecycleSnapshot.RunningBuild.unknown(runningBuild);
  }

  private CoreSupportLifecycleSnapshot.RunningBuild activeRunningBuildSnapshot(
      CoreSupportLifecycleEntry running) {
    return new CoreSupportLifecycleSnapshot.RunningBuild(
        runningBuild,
        running.lifecycleStatus(),
        text(running.statusEffectiveAt()),
        text(running.fullSupportUntil()),
        text(running.securityFixesUntil()),
        text(running.deprecationEffectiveAt()),
        text(running.endOfSupportAt()),
        running.replacementBuild(),
        running.recoveryGuidance(),
        running.advisoryIds(),
        running.reasonCodes());
  }

  private CoreSupportLifecycleSnapshot.RunningBuild effectiveRevocationSnapshot(
      CoreSupportLifecycleEntry running) {
    Integer replacementBuild = null;
    String recoveryGuidance = null;
    RunningRevocationProjection projection = runningRevocationProjection;
    if (projection != null && projection.buildVersion() == running.buildVersion()) {
      replacementBuild = projection.replacementBuild();
      recoveryGuidance = projection.recoveryGuidance();
    }
    return new CoreSupportLifecycleSnapshot.RunningBuild(
        runningBuild,
        running.lifecycleStatus(),
        text(running.statusEffectiveAt()),
        null,
        null,
        null,
        null,
        replacementBuild,
        recoveryGuidance,
        running.advisoryIds(),
        running.reasonCodes());
  }

  /** Returns the currently accepted descriptor edition for subscription seeding. */
  synchronized int acceptedEditionSeed() {
    if (descriptor == null || descriptor.descriptorEdition() > Integer.MAX_VALUE) {
      return 0;
    }
    return Math.toIntExact(descriptor.descriptorEdition());
  }

  /**
   * Returns whether an effective authenticated lifecycle entry revokes one package build.
   *
   * <p>Staleness does not make an accepted revocation safe: build revocation is terminal, while a
   * later valid descriptor can only preserve it. A successor whose activation is ahead of the local
   * clock therefore keeps only predecessor-effective revocations active; a revocation first
   * introduced by that successor waits for descriptor activation even when its incident timestamp
   * is earlier. Unknown builds and not-yet-effective revocation entries remain outside this narrow
   * veto rather than being assigned an invented lifecycle status.
   *
   * @param buildVersion integer package build advertised by {@code core-info.json}
   * @return {@code true} only when the accepted descriptor effectively revokes that exact build
   */
  synchronized boolean isBuildRevoked(int buildVersion) {
    if (descriptor == null) {
      return false;
    }
    Instant now = clock.instant();
    CoreSupportLifecycleEntry entry = descriptor.entriesByBuild().get(buildVersion);
    Instant activation = revocationActivationByBuild.get(buildVersion);
    return entry != null
        && entry.lifecycleStatus() == CoreSupportLifecycleStatus.REVOKED
        && activation != null
        && !now.isBefore(activation)
        && !now.isBefore(entry.statusEffectiveAt());
  }

  /**
   * Returns the delay until one authenticated build revocation becomes enforceable.
   *
   * <p>The delay is derived from the persisted activation state and this component's clock. It is
   * absent for unknown, non-revoked, or already-effective builds. Callers must recheck {@link
   * #isBuildRevoked(int)} when the delay expires because a newer descriptor or a wall-clock
   * adjustment may have changed the effective state.
   *
   * @param buildVersion integer package build advertised by {@code core-info.json}
   * @return a positive delay in milliseconds, or empty when no future recheck is required
   */
  synchronized OptionalLong pendingBuildRevocationDelayMillis(int buildVersion) {
    if (descriptor == null) {
      return OptionalLong.empty();
    }
    CoreSupportLifecycleEntry entry = descriptor.entriesByBuild().get(buildVersion);
    Instant activation = revocationActivationByBuild.get(buildVersion);
    Instant now = clock.instant();
    if (entry == null
        || entry.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED
        || activation == null
        || !now.isBefore(activation)) {
      return OptionalLong.empty();
    }
    return OptionalLong.of(Math.max(1, Duration.between(now, activation).toMillis()));
  }

  /**
   * Executes one package action while lifecycle state continues to authorize its build.
   *
   * <p>Holding the lifecycle-state monitor through the action gives descriptor acceptance, trust
   * changes, compromise invalidation, and installer launch one linear order. A null build retains
   * the legacy noninteger descriptor behavior but still holds this monitor so a concurrent trust
   * transition cannot overtake the action.
   *
   * @param buildVersion selected integer package build, or {@code null} for a legacy descriptor
   * @param action bounded non-null action to execute when the build is not effectively revoked
   * @param <T> action result type
   * @return action result, or empty when lifecycle state revokes the selected build
   */
  synchronized <T> Optional<T> withNonRevokedBuild(Integer buildVersion, Supplier<T> action) {
    Objects.requireNonNull(action, "action");
    if (buildVersion != null && isBuildRevoked(buildVersion)) {
      return Optional.empty();
    }
    return Optional.of(Objects.requireNonNull(action.get(), "action result"));
  }

  /** Returns whether persisted update-key compromise evidence has invalidated lifecycle trust. */
  synchronized boolean isUpdateKeyTrustInvalidated() {
    return trustInvalidated;
  }

  private void loadPersisted() {
    if (trustInvalidated) {
      lastFailureCode = LIFECYCLE_TRUST_INVALIDATED_WARNING;
      return;
    }
    try {
      if (restoreTrustInvalidation(store.trustInvalidationStatus())) {
        return;
      }
      CoreSupportLifecycleStore.StoredDescriptor stored = store.load();
      if (stored == null) {
        restoreTrustInvalidation(store.trustInvalidationStatus());
        return;
      }
      CoreSupportLifecycleDescriptor persisted = parser.parsePersisted(stored.bytes(), trust);
      validateRunningIdentity(persisted);
      descriptor = persisted;
      DecodedRevocationState revocationState =
          decodeRevocationState(stored.revocationState(), persisted);
      revocationActivationByBuild = revocationState.activations();
      runningRevocationProjection = revocationState.runningProjection();
      lastVerifiedAt = stored.verifiedAt();
    } catch (IOException | IllegalArgumentException _) {
      descriptor = null;
      revocationActivationByBuild = Map.of();
      runningRevocationProjection = null;
      lastVerifiedAt = null;
      lastFailureCode = "lifecycle_persisted_state_invalid";
    }
  }

  private boolean restoreTrustInvalidation(
      CoreSupportLifecycleStore.TrustInvalidationStatus status) {
    if (status == CoreSupportLifecycleStore.TrustInvalidationStatus.ABSENT) {
      return false;
    }
    trustInvalidated = true;
    descriptor = null;
    revocationActivationByBuild = Map.of();
    runningRevocationProjection = null;
    lastVerifiedAt = null;
    lastFailureCode =
        status == CoreSupportLifecycleStore.TrustInvalidationStatus.VALID
            ? LIFECYCLE_TRUST_INVALIDATED_WARNING
            : "lifecycle_trust_invalidation_marker_invalid";
    return true;
  }

  private void validateRunningIdentity(CoreSupportLifecycleDescriptor candidate) {
    CoreSupportLifecycleEntry running = candidate.entriesByBuild().get(runningBuild);
    if (running == null || isDevelopmentCommit(runningSourceCommit)) {
      return;
    }
    if (!RUNTIME_SOURCE_COMMIT.matcher(runningSourceCommit).matches()
        || !running.sourceCommit().startsWith(runningSourceCommit)) {
      throw new IllegalArgumentException("running build source identity conflicts with descriptor");
    }
  }

  private static boolean isDevelopmentCommit(String commit) {
    return commit == null
        || commit.isBlank()
        || commit.startsWith("@")
        || "unknown".equalsIgnoreCase(commit);
  }

  private static void validateSuccessor(
      CoreSupportLifecycleDescriptor previous, CoreSupportLifecycleDescriptor candidate) {
    if (previous == null) {
      if (candidate.descriptorEdition() != 1
          || candidate.previousDescriptorEdition() != null
          || candidate.previousDescriptorDigest() != null) {
        throw new IllegalArgumentException(
            "first lifecycle descriptor must be the authenticated root edition");
      }
      return;
    }
    if (candidate.descriptorEdition() != previous.descriptorEdition() + 1
        || !Objects.equals(candidate.previousDescriptorEdition(), previous.descriptorEdition())
        || !Objects.equals(candidate.previousDescriptorDigest(), previous.descriptorDigest())) {
      throw new IllegalArgumentException("lifecycle descriptor rollback, replay, gap, or fork");
    }

    Map<Integer, CoreSupportLifecycleEntry> oldEntries = previous.entriesByBuild();
    Map<Integer, CoreSupportLifecycleEntry> newEntries = candidate.entriesByBuild();
    if (!newEntries.keySet().containsAll(oldEntries.keySet())) {
      throw new IllegalArgumentException("lifecycle descriptor omitted a published build");
    }
    int oldTip = previous.entries().getLast().buildVersion();
    for (CoreSupportLifecycleEntry entry : candidate.entries()) {
      CoreSupportLifecycleEntry old = oldEntries.get(entry.buildVersion());
      if (old == null) {
        if (entry.buildVersion() <= oldTip) {
          throw new IllegalArgumentException("lifecycle descriptor inserted an older build");
        }
        continue;
      }
      validateImmutableIdentity(old, entry);
      validateDeadlineClocks(old, entry);
      validateEntryTransition(old, entry);
    }
  }

  private static void validateImmutableIdentity(
      CoreSupportLifecycleEntry old, CoreSupportLifecycleEntry next) {
    if (!old.releaseId().equals(next.releaseId())
        || old.buildVersion() != next.buildVersion()
        || !old.tag().equals(next.tag())
        || !old.sourceCommit().equals(next.sourceCommit())
        || !old.productDigest().equals(next.productDigest())
        || !old.publicationReceiptDigest().equals(next.publicationReceiptDigest())
        || !old.baselineDigest().equals(next.baselineDigest())
        || !old.publishedAt().equals(next.publishedAt())) {
      throw new IllegalArgumentException("lifecycle descriptor rewrote published release identity");
    }
  }

  private static void validateDeadlineClocks(
      CoreSupportLifecycleEntry old, CoreSupportLifecycleEntry next) {
    if (!Objects.equals(old.fullSupportUntil(), next.fullSupportUntil())
        || !Objects.equals(old.securityFixesUntil(), next.securityFixesUntil())
        || !Objects.equals(old.deprecationEffectiveAt(), next.deprecationEffectiveAt())
        || !Objects.equals(old.endOfSupportAt(), next.endOfSupportAt())
        || (old.securityRevocationEffectiveAt() != null
            && !Objects.equals(
                old.securityRevocationEffectiveAt(), next.securityRevocationEffectiveAt()))) {
      throw new IllegalArgumentException("lifecycle descriptor reset a published support clock");
    }
  }

  private static void validateEntryTransition(
      CoreSupportLifecycleEntry old, CoreSupportLifecycleEntry next) {
    if (old.equals(next)) {
      return;
    }
    if (old.lifecycleStatus() == CoreSupportLifecycleStatus.REVOKED) {
      validateTerminalRevocation(old, next);
      return;
    }
    if (next.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED) {
      int oldRank = normalRank(old.lifecycleStatus());
      int nextRank = normalRank(next.lifecycleStatus());
      if (nextRank < oldRank) {
        throw new IllegalArgumentException("build lifecycle transition moved backward");
      }
    }
    if (next.statusEffectiveAt().isBefore(old.statusEffectiveAt())) {
      throw new IllegalArgumentException("build lifecycle effective time moved backward");
    }
    if (next.lifecycleStatus() == old.lifecycleStatus()
        && !next.statusEffectiveAt().equals(old.statusEffectiveAt())) {
      throw new IllegalArgumentException("unchanged build lifecycle reset its effective time");
    }
  }

  private static void validateTerminalRevocation(
      CoreSupportLifecycleEntry old, CoreSupportLifecycleEntry next) {
    if (next.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED
        || !next.statusEffectiveAt().equals(old.statusEffectiveAt())
        || !next.advisoryIds().equals(old.advisoryIds())
        || !next.reasonCodes().equals(old.reasonCodes())) {
      throw new IllegalArgumentException("revoked build lifecycle is terminal");
    }
  }

  private static int normalRank(CoreSupportLifecycleStatus status) {
    return switch (status) {
      case CURRENT_STABLE -> 0;
      case SUPPORTED_MAINTENANCE -> 1;
      case SECURITY_FIXES_ONLY -> 2;
      case DEPRECATED -> 3;
      case END_OF_SUPPORT -> 4;
      case REVOKED -> Integer.MAX_VALUE;
    };
  }

  private Map<Integer, Instant> revocationActivationsForSuccessor(
      CoreSupportLifecycleDescriptor previous, CoreSupportLifecycleDescriptor candidate) {
    Map<Integer, CoreSupportLifecycleEntry> previousEntries =
        previous == null ? Map.of() : previous.entriesByBuild();
    HashMap<Integer, Instant> activations = new HashMap<>();
    for (CoreSupportLifecycleEntry entry : candidate.entries()) {
      if (entry.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED) {
        continue;
      }
      CoreSupportLifecycleEntry old = previousEntries.get(entry.buildVersion());
      Instant activation = candidate.effectiveAt();
      if (previous != null
          && old != null
          && old.lifecycleStatus() == CoreSupportLifecycleStatus.REVOKED) {
        activation =
            revocationActivationByBuild.getOrDefault(entry.buildVersion(), previous.effectiveAt());
      }
      activations.put(entry.buildVersion(), activation);
    }
    return Map.copyOf(activations);
  }

  private RunningRevocationProjection runningRevocationProjectionForSuccessor(
      CoreSupportLifecycleDescriptor previous, CoreSupportLifecycleDescriptor candidate) {
    Instant now = clock.instant();
    if (previous == null || !now.isBefore(candidate.effectiveAt())) {
      return null;
    }
    CoreSupportLifecycleEntry previousRunning = previous.entriesByBuild().get(runningBuild);
    CoreSupportLifecycleEntry candidateRunning = candidate.entriesByBuild().get(runningBuild);
    Instant priorActivation = revocationActivationByBuild.get(runningBuild);
    if (previousRunning == null
        || candidateRunning == null
        || previousRunning.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED
        || candidateRunning.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED
        || priorActivation == null
        || now.isBefore(priorActivation)
        || now.isBefore(previousRunning.statusEffectiveAt())) {
      return null;
    }
    if (now.isBefore(previous.effectiveAt())) {
      return rebindRunningRevocationProjection(previous, candidate);
    }
    return new RunningRevocationProjection(
        runningBuild,
        previous.descriptorDigest(),
        candidate.descriptorDigest(),
        previousRunning.replacementBuild(),
        previousRunning.recoveryGuidance());
  }

  private RunningRevocationProjection rebindRunningRevocationProjection(
      CoreSupportLifecycleDescriptor previous, CoreSupportLifecycleDescriptor candidate) {
    RunningRevocationProjection projection = runningRevocationProjection;
    if (projection == null) {
      return null;
    }
    if (projection.sourceDescriptorDigest().equals(previous.descriptorDigest())
        && projection.targetDescriptorDigest().equals(candidate.descriptorDigest())) {
      return projection;
    }
    if (!projection.targetDescriptorDigest().equals(previous.descriptorDigest())) {
      return null;
    }
    return new RunningRevocationProjection(
        projection.buildVersion(),
        previous.descriptorDigest(),
        candidate.descriptorDigest(),
        projection.replacementBuild(),
        projection.recoveryGuidance());
  }

  private byte[] encodeRevocationState(
      Map<Integer, Instant> activations, RunningRevocationProjection runningProjection) {
    ArrayList<Map<String, Object>> entries = new ArrayList<>(activations.size());
    activations.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(
            activation -> {
              LinkedHashMap<String, Object> value = new LinkedHashMap<>();
              value.put(BUILD_VERSION_FIELD, Integer.toString(activation.getKey()));
              value.put("effectiveAt", activation.getValue().toString());
              entries.add(value);
            });
    LinkedHashMap<String, Object> root = new LinkedHashMap<>();
    root.put(SCHEMA_VERSION_FIELD, REVOCATION_STATE_SCHEMA_VERSION);
    root.put(UPDATE_KEY_IDENTITY_DIGEST_FIELD, trust.updateKeyIdentityDigest());
    root.put(UPDATE_KEY_SCOPE_FIELD, trust.updateKeyScope());
    root.put(UPDATE_KEY_DOC_NAME_FIELD, trust.updateKeyDocName());
    root.put(REVOCATION_ACTIVATIONS_FIELD, entries);
    root.put(
        RUNNING_REVOCATION_PROJECTION_FIELD,
        runningProjection == null ? null : encodeRunningRevocationProjection(runningProjection));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }

  private static Map<String, Object> encodeRunningRevocationProjection(
      RunningRevocationProjection projection) {
    LinkedHashMap<String, Object> value = new LinkedHashMap<>();
    value.put(BUILD_VERSION_FIELD, Integer.toString(projection.buildVersion()));
    value.put(SOURCE_DESCRIPTOR_DIGEST_FIELD, projection.sourceDescriptorDigest());
    value.put(TARGET_DESCRIPTOR_DIGEST_FIELD, projection.targetDescriptorDigest());
    value.put(
        "replacementBuild",
        projection.replacementBuild() == null
            ? null
            : Integer.toString(projection.replacementBuild()));
    value.put("recoveryGuidance", projection.recoveryGuidance());
    return value;
  }

  private DecodedRevocationState decodeRevocationState(
      byte[] bytes, CoreSupportLifecycleDescriptor persisted) {
    DecodedRevocationState fallback =
        new DecodedRevocationState(conservativeRevocationFallback(persisted), null);
    if (bytes.length == 0) {
      return fallback;
    }
    try {
      Map<String, Object> root = JsonMini.parseObject(new String(bytes, StandardCharsets.UTF_8));
      long schemaVersion = revocationStateSchemaVersion(root);
      if (!hasExactRevocationStateFields(root, schemaVersion)
          || !revocationStateMatchesTrust(root)) {
        return fallback;
      }
      Map<Integer, Instant> decoded = decodeRevocationActivations(root);
      if (!activationsMatchDescriptor(decoded, persisted)) {
        return fallback;
      }
      RunningRevocationProjection runningProjection =
          decodeRunningRevocationProjection(root, schemaVersion, decoded, persisted);
      return new DecodedRevocationState(Map.copyOf(decoded), runningProjection);
    } catch (IllegalArgumentException _) {
      return fallback;
    }
  }

  private static long revocationStateSchemaVersion(Map<String, Object> root) {
    if (!(root.get(SCHEMA_VERSION_FIELD) instanceof Long schemaVersion)) {
      throw new IllegalArgumentException("invalid lifecycle revocation state schema");
    }
    return schemaVersion;
  }

  private static boolean hasExactRevocationStateFields(
      Map<String, Object> root, long schemaVersion) {
    boolean commonFields =
        root.containsKey(SCHEMA_VERSION_FIELD)
            && root.containsKey(UPDATE_KEY_IDENTITY_DIGEST_FIELD)
            && root.containsKey(UPDATE_KEY_SCOPE_FIELD)
            && root.containsKey(UPDATE_KEY_DOC_NAME_FIELD)
            && root.containsKey(REVOCATION_ACTIVATIONS_FIELD);
    if (!commonFields) {
      return false;
    }
    if (schemaVersion == LEGACY_REVOCATION_STATE_SCHEMA_VERSION) {
      return root.size() == 5;
    }
    return (schemaVersion == SINGLE_BINDING_REVOCATION_STATE_SCHEMA_VERSION
            || schemaVersion == REVOCATION_STATE_SCHEMA_VERSION)
        && root.size() == 6
        && root.containsKey(RUNNING_REVOCATION_PROJECTION_FIELD);
  }

  private boolean revocationStateMatchesTrust(Map<String, Object> root) {
    return Objects.equals(
            root.get(UPDATE_KEY_IDENTITY_DIGEST_FIELD), trust.updateKeyIdentityDigest())
        && Objects.equals(root.get(UPDATE_KEY_SCOPE_FIELD), trust.updateKeyScope())
        && Objects.equals(root.get(UPDATE_KEY_DOC_NAME_FIELD), trust.updateKeyDocName());
  }

  private static Map<Integer, Instant> decodeRevocationActivations(Map<String, Object> root) {
    Object value = root.get(REVOCATION_ACTIVATIONS_FIELD);
    if (!(value instanceof List<?> entries) || entries.size() > MAX_REVOCATION_STATE_ENTRIES) {
      throw new IllegalArgumentException("invalid lifecycle revocation activation state");
    }
    HashMap<Integer, Instant> decoded = new HashMap<>();
    for (Object item : entries) {
      if (!(item instanceof Map<?, ?> entry)
          || entry.size() != 2
          || !(entry.get(BUILD_VERSION_FIELD) instanceof String buildText)
          || !(entry.get("effectiveAt") instanceof String effectiveText)) {
        throw new IllegalArgumentException("invalid lifecycle revocation activation entry");
      }
      int build = Integer.parseInt(buildText);
      if (build <= 0
          || !Integer.toString(build).equals(buildText)
          || decoded.put(build, Instant.parse(effectiveText)) != null) {
        throw new IllegalArgumentException("invalid lifecycle revocation activation build");
      }
    }
    return decoded;
  }

  private RunningRevocationProjection decodeRunningRevocationProjection(
      Map<String, Object> root,
      long schemaVersion,
      Map<Integer, Instant> activations,
      CoreSupportLifecycleDescriptor persisted) {
    if (schemaVersion == LEGACY_REVOCATION_STATE_SCHEMA_VERSION) {
      return null;
    }
    Object value = root.get(RUNNING_REVOCATION_PROJECTION_FIELD);
    if (value == null) {
      return null;
    }
    int expectedFields = schemaVersion == SINGLE_BINDING_REVOCATION_STATE_SCHEMA_VERSION ? 4 : 5;
    if (!(value instanceof Map<?, ?> projection)
        || projection.size() != expectedFields
        || !(projection.get(BUILD_VERSION_FIELD) instanceof String buildText)
        || !(projection.get(SOURCE_DESCRIPTOR_DIGEST_FIELD)
            instanceof String sourceDescriptorDigest)) {
      throw new IllegalArgumentException("invalid running-build revocation projection");
    }
    String targetDescriptorDigest = targetDescriptorDigest(projection, schemaVersion, persisted);
    int buildVersion = parseCanonicalBuild(buildText);
    CoreSupportLifecycleEntry running = persisted.entriesByBuild().get(buildVersion);
    Instant activation = activations.get(buildVersion);
    if (buildVersion != runningBuild
        || running == null
        || running.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED
        || activation == null
        || !activation.isBefore(persisted.effectiveAt())
        || !projectionMatchesPersistedDescriptor(
            sourceDescriptorDigest, targetDescriptorDigest, persisted)) {
      throw new IllegalArgumentException("running-build revocation projection is not predecessor");
    }
    Integer replacementBuild = parseOptionalCanonicalBuild(projection.get("replacementBuild"));
    String recoveryGuidance = parseOptionalRecoveryGuidance(projection.get("recoveryGuidance"));
    if ((replacementBuild == null) == (recoveryGuidance == null)) {
      throw new IllegalArgumentException(
          "running-build revocation projection lacks exact guidance");
    }
    if (replacementBuild != null
        && (replacementBuild == runningBuild
            || !persisted.entriesByBuild().containsKey(replacementBuild))) {
      throw new IllegalArgumentException("running-build replacement is outside release inventory");
    }
    return new RunningRevocationProjection(
        buildVersion,
        sourceDescriptorDigest,
        targetDescriptorDigest,
        replacementBuild,
        recoveryGuidance);
  }

  private static String targetDescriptorDigest(
      Map<?, ?> projection, long schemaVersion, CoreSupportLifecycleDescriptor persisted) {
    if (schemaVersion == SINGLE_BINDING_REVOCATION_STATE_SCHEMA_VERSION) {
      return persisted.descriptorDigest();
    }
    Object value = projection.get(TARGET_DESCRIPTOR_DIGEST_FIELD);
    if (!(value instanceof String targetDescriptorDigest)
        || CoreSupportLifecycleParser.isNotCanonicalDigest(targetDescriptorDigest)) {
      throw new IllegalArgumentException("invalid running-build revocation target digest");
    }
    return targetDescriptorDigest;
  }

  private static boolean projectionMatchesPersistedDescriptor(
      String sourceDescriptorDigest,
      String targetDescriptorDigest,
      CoreSupportLifecycleDescriptor persisted) {
    if (CoreSupportLifecycleParser.isNotCanonicalDigest(sourceDescriptorDigest)
        || sourceDescriptorDigest.equals(targetDescriptorDigest)) {
      return false;
    }
    boolean completedTransition =
        targetDescriptorDigest.equals(persisted.descriptorDigest())
            && Objects.equals(sourceDescriptorDigest, persisted.previousDescriptorDigest());
    boolean preparedTransition = sourceDescriptorDigest.equals(persisted.descriptorDigest());
    return completedTransition || preparedTransition;
  }

  private static int parseCanonicalBuild(String text) {
    int build = Integer.parseInt(text);
    if (build <= 0 || !Integer.toString(build).equals(text)) {
      throw new IllegalArgumentException("invalid lifecycle revocation projection build");
    }
    return build;
  }

  private static Integer parseOptionalCanonicalBuild(Object value) {
    if (value == null) {
      return null;
    }
    if (!(value instanceof String text)) {
      throw new IllegalArgumentException("invalid lifecycle revocation replacement build");
    }
    return parseCanonicalBuild(text);
  }

  private static String parseOptionalRecoveryGuidance(Object value) {
    if (value == null) {
      return null;
    }
    if (!(value instanceof String text)
        || !CoreSupportLifecycleParser.isSafeRecoveryGuidance(text)) {
      throw new IllegalArgumentException("invalid lifecycle revocation recovery guidance");
    }
    return text;
  }

  private static boolean activationsMatchDescriptor(
      Map<Integer, Instant> activations, CoreSupportLifecycleDescriptor descriptor) {
    for (CoreSupportLifecycleEntry entry : descriptor.entries()) {
      if (entry.lifecycleStatus() != CoreSupportLifecycleStatus.REVOKED) {
        continue;
      }
      Instant activation = activations.get(entry.buildVersion());
      if (activation == null
          || activation.isBefore(entry.statusEffectiveAt())
          || activation.isAfter(descriptor.effectiveAt())) {
        return false;
      }
    }
    return true;
  }

  private static Map<Integer, Instant> conservativeRevocationFallback(
      CoreSupportLifecycleDescriptor descriptor) {
    HashMap<Integer, Instant> activations = new HashMap<>();
    descriptor.entries().stream()
        .filter(entry -> entry.lifecycleStatus() == CoreSupportLifecycleStatus.REVOKED)
        .forEach(entry -> activations.put(entry.buildVersion(), entry.statusEffectiveAt()));
    return Map.copyOf(activations);
  }

  private CoreSupportLifecycleSnapshot.DescriptorVerification verification(
      CoreSupportLifecycleDescriptor currentDescriptor) {
    return new CoreSupportLifecycleSnapshot.DescriptorVerification(
        currentDescriptor.descriptorEdition(),
        currentDescriptor.descriptorDigest(),
        text(lastVerifiedAt));
  }

  private CoreSupportLifecycleSnapshot.Recommendation recommendation(
      CoreSupportLifecycleDescriptor currentDescriptor, boolean effective) {
    if (!effective) {
      return new CoreSupportLifecycleSnapshot.Recommendation(null, null, false);
    }
    Integer recommendedBuild = currentDescriptor.recommendedBuild();
    return new CoreSupportLifecycleSnapshot.Recommendation(
        currentDescriptor.currentStableBuild(),
        recommendedBuild,
        recommendedBuild != null && recommendedBuild > runningBuild);
  }

  private List<String> runningBuildMissingWarnings(boolean effective) {
    ArrayList<String> warnings = new ArrayList<>();
    warnings.add(RUNNING_BUILD_NOT_IN_LIFECYCLE_INVENTORY_WARNING);
    if (!effective) {
      warnings.add("lifecycle_descriptor_not_effective");
    }
    if (lastFailureCode != null) {
      warnings.add(lastFailureCode);
    }
    return List.copyOf(warnings);
  }

  private static void addStatusWarning(List<String> warnings, CoreSupportLifecycleStatus status) {
    switch (status) {
      case CURRENT_STABLE -> {
        // Healthy status has no warning.
      }
      case SUPPORTED_MAINTENANCE -> warnings.add("supported_build_upgrade_available");
      case SECURITY_FIXES_ONLY -> warnings.add("security_fixes_only");
      case DEPRECATED -> warnings.add("build_deprecated");
      case END_OF_SUPPORT -> warnings.add("build_end_of_support");
      case REVOKED -> warnings.add("build_revoked");
    }
  }

  private record DecodedRevocationState(
      Map<Integer, Instant> activations, RunningRevocationProjection runningProjection) {
    private DecodedRevocationState {
      activations = Map.copyOf(activations);
    }
  }

  private record RunningRevocationProjection(
      int buildVersion,
      String sourceDescriptorDigest,
      String targetDescriptorDigest,
      Integer replacementBuild,
      String recoveryGuidance) {}

  private static String text(Instant instant) {
    return instant == null ? null : instant.toString();
  }

  private static String safeFailureCode(String value) {
    if (value == null || !value.matches("[a-z0-9_]{1,64}")) {
      return "lifecycle_validation_failed";
    }
    return value;
  }
}
