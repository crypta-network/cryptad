package network.crypta.runtime.updater;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
    Instant verifiedAt = clock.instant();
    store.save(bytes, verifiedAt);
    descriptor = candidate;
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
    if (descriptor == null) {
      return CoreSupportLifecycleSnapshot.unknown(
          runningBuild, List.of(lastFailureCode == null ? "lifecycle_unknown" : lastFailureCode));
    }
    Map<Integer, CoreSupportLifecycleEntry> byBuild = descriptor.entriesByBuild();
    CoreSupportLifecycleEntry running = byBuild.get(runningBuild);
    if (running == null) {
      return new CoreSupportLifecycleSnapshot(
          false,
          !clock.instant().isBefore(descriptor.staleAt()),
          CoreSupportLifecycleSnapshot.RunningBuild.unknown(runningBuild),
          new CoreSupportLifecycleSnapshot.Recommendation(
              descriptor.currentStableBuild(),
              descriptor.recommendedBuild(),
              descriptor.recommendedBuild() != null
                  && descriptor.recommendedBuild() > runningBuild),
          verification(),
          runningBuildMissingWarnings());
    }

    Instant now = clock.instant();
    boolean effective = !now.isBefore(descriptor.effectiveAt());
    boolean stale = !now.isBefore(descriptor.staleAt());
    ArrayList<String> warningCodes = new ArrayList<>();
    if (!effective) {
      warningCodes.add("lifecycle_descriptor_not_effective");
    }
    if (stale) {
      warningCodes.add("lifecycle_descriptor_stale");
    }
    addStatusWarning(warningCodes, running.lifecycleStatus());
    if (lastFailureCode != null) {
      warningCodes.add(lastFailureCode);
    }
    CoreSupportLifecycleSnapshot.RunningBuild runningSnapshot =
        new CoreSupportLifecycleSnapshot.RunningBuild(
            runningBuild,
            effective ? running.lifecycleStatus() : null,
            effective ? text(running.statusEffectiveAt()) : null,
            text(running.fullSupportUntil()),
            text(running.securityFixesUntil()),
            text(running.deprecationEffectiveAt()),
            text(running.endOfSupportAt()),
            running.replacementBuild(),
            running.recoveryGuidance(),
            running.advisoryIds(),
            running.reasonCodes());
    return new CoreSupportLifecycleSnapshot(
        effective,
        stale,
        runningSnapshot,
        new CoreSupportLifecycleSnapshot.Recommendation(
            descriptor.currentStableBuild(),
            descriptor.recommendedBuild(),
            descriptor.recommendedBuild() != null && descriptor.recommendedBuild() > runningBuild),
        verification(),
        List.copyOf(warningCodes));
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
   * later valid descriptor can only preserve it. A successor descriptor whose activation time is
   * still ahead of the local clock therefore cannot suspend a revocation that is already effective
   * according to the preserved entry. Unknown builds and not-yet-effective revocation entries
   * remain outside this narrow veto rather than being assigned an invented lifecycle status.
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
    return entry != null
        && entry.lifecycleStatus() == CoreSupportLifecycleStatus.REVOKED
        && !now.isBefore(entry.statusEffectiveAt());
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
      lastVerifiedAt = stored.verifiedAt();
    } catch (IOException | IllegalArgumentException _) {
      descriptor = null;
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

  private CoreSupportLifecycleSnapshot.DescriptorVerification verification() {
    return new CoreSupportLifecycleSnapshot.DescriptorVerification(
        descriptor.descriptorEdition(), descriptor.descriptorDigest(), text(lastVerifiedAt));
  }

  private List<String> runningBuildMissingWarnings() {
    return lastFailureCode == null
        ? List.of(RUNNING_BUILD_NOT_IN_LIFECYCLE_INVENTORY_WARNING)
        : List.of(RUNNING_BUILD_NOT_IN_LIFECYCLE_INVENTORY_WARNING, lastFailureCode);
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
