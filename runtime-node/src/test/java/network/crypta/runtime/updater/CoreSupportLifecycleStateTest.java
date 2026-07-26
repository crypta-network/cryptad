package network.crypta.runtime.updater;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CoreSupportLifecycleStateTest {
  private static final String SHA_256_PREFIX = "sha256:";
  private static final String IDENTITY_DIGEST =
      SHA_256_PREFIX + "b6386982e7eed893448339eed564fcdc140547266b0dc70978ddfa345f6136d7";
  private static final String ROOT_DIGEST =
      SHA_256_PREFIX + "9ee26a76598bf0a9a3a9f4b5aaf1b6583f0a4229fffc044e262905404cd554da";
  private static final Instant VERIFIED_AT = Instant.parse("2026-01-02T12:00:00Z");
  private static final Instant RESTARTED_AT = Instant.parse("2026-01-05T12:00:00Z");
  private static final String TRUST_INVALIDATED_WARNING = "lifecycle_trust_invalidated";
  private static final String BUILD_REVOKED_WARNING = "build_revoked";
  private static final String LIFECYCLE_STATE_PATH = "updates/core/lifecycle.json";
  private static final String REVOCATION_STATE_SUFFIX = ".revocation-activations";
  private static final String DESCRIPTOR_DIGEST_FIELD = "descriptorDigest";
  private static final String ENTRIES_FIELD = "entries";
  private static final String REPLACEMENT_BUILD_FIELD = "replacementBuild";
  private static final String RECOVERY_GUIDANCE_FIELD = "recoveryGuidance";
  private static final String REVOKED_STATUS = "revoked";
  private static final String REVOCATION_EFFECTIVE_AT = "2026-01-02T00:00:00Z";
  private static final String FUTURE_DESCRIPTOR_EFFECTIVE_AT = "2026-01-03T00:00:00Z";
  private static final String SECOND_FUTURE_DESCRIPTOR_EFFECTIVE_AT = "2026-01-04T00:00:00Z";
  private static final String ACTIVE_RECOVERY_GUIDANCE =
      "Restore from a verified backup and wait for an authenticated replacement.";
  private static final String FUTURE_RECOVERY_GUIDANCE =
      "Use the successor recovery procedure only after descriptor activation.";
  private static final String SECOND_FUTURE_RECOVERY_GUIDANCE =
      "Use the second successor recovery procedure after its activation.";
  private static final String SECURITY_ADVISORY_ID = "CRYPTA-2026-001";
  private static final String REVOCATION_REASON_CODE = "critical-release-defect";

  @Test
  void accept_whenCertificationFixtureIsValid_expectKnownCurrentStableSnapshot(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);

    state.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);

    CoreSupportLifecycleSnapshot snapshot = state.snapshot();
    assertTrue(snapshot.known());
    assertFalse(snapshot.stale());
    assertEquals(100, snapshot.running().build());
    assertEquals("current-stable", snapshot.running().status().wireValue());
    assertEquals(100, snapshot.recommendation().currentStableBuild());
    assertEquals(ROOT_DIGEST, snapshot.descriptor().digest());
    assertEquals(VERIFIED_AT.toString(), snapshot.descriptor().lastVerifiedAt());
  }

  @Test
  void accept_whenRuntimeUsesAbbreviatedSourceCommit_expectPublishedIdentityMatches(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT, "a".repeat(10));

    state.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);

    assertTrue(state.snapshot().known());
  }

  @Test
  void accept_whenAbbreviatedSourceCommitDiffers_expectIdentityConflict(@TempDir Path tempDir)
      throws IOException {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT, "b".repeat(10));
    byte[] fixture = CoreSupportLifecycleParserTest.fixtureBytes();

    assertThrows(IllegalArgumentException.class, () -> state.accept(fixture, 1));
  }

  @Test
  void accept_whenRuntimeSourceCommitIsNotHex_expectIdentityConflict(@TempDir Path tempDir)
      throws IOException {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT, "not-a-commit");
    byte[] fixture = CoreSupportLifecycleParserTest.fixtureBytes();

    assertThrows(IllegalArgumentException.class, () -> state.accept(fixture, 1));
  }

  @Test
  void constructor_whenRestartLoadsPersistedState_expectOriginalVerificationTime(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState first = state(tempDir, VERIFIED_AT);
    first.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);

    CoreSupportLifecycleState restarted = state(tempDir, RESTARTED_AT);

    assertTrue(restarted.snapshot().known());
    assertEquals(VERIFIED_AT.toString(), restarted.snapshot().descriptor().lastVerifiedAt());
  }

  @Test
  void invalidateCompromisedUpdateKey_whenStateWasAccepted_expectUnknownAcrossRestart(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState accepted = state(tempDir, VERIFIED_AT);
    byte[] fixture = CoreSupportLifecycleParserTest.fixtureBytes();
    accepted.accept(fixture, 1);

    boolean persistenceCleared = accepted.invalidateCompromisedUpdateKey();
    CoreSupportLifecycleState restarted = state(tempDir, RESTARTED_AT);

    assertTrue(persistenceCleared);
    assertFalse(accepted.snapshot().known());
    assertEquals(List.of(TRUST_INVALIDATED_WARNING), accepted.snapshot().warnings());
    assertThrows(IllegalArgumentException.class, () -> accepted.accept(fixture, 1));
    accepted.recordFailure("lifecycle_validation_failed");
    accepted.changeTrust(
        new CoreSupportLifecycleParser.TrustBinding(
            SHA_256_PREFIX + "0".repeat(64),
            SHA_256_PREFIX + "0".repeat(64) + "/support-lifecycle/0",
            "support-lifecycle"));
    assertTrue(accepted.isUpdateKeyTrustInvalidated());
    assertEquals(List.of(TRUST_INVALIDATED_WARNING), accepted.snapshot().warnings());
    assertTrue(restarted.isUpdateKeyTrustInvalidated());
    assertFalse(restarted.snapshot().known());
    assertEquals(List.of(TRUST_INVALIDATED_WARNING), restarted.snapshot().warnings());
    assertThrows(IllegalArgumentException.class, () -> restarted.accept(fixture, 1));
  }

  @Test
  void invalidateCompromisedUpdateKey_whenPersistenceThrowsUnchecked_expectTrustFailsClosed(
      @TempDir Path tempDir) {
    CoreSupportLifecycleStore.PersistenceSync failingPersistence =
        new CoreSupportLifecycleStore.PersistenceSync() {
          @Override
          public void forceFile(Path file) {
            throw new IllegalStateException("simulated persistence failure");
          }

          @Override
          public void publish(Path temporary, Path target, boolean replaceExisting) {
            throw new IllegalStateException("simulated persistence failure");
          }
        };
    CoreSupportLifecycleState state =
        new CoreSupportLifecycleState(
            new CoreSupportLifecycleStore(
                tempDir.resolve(LIFECYCLE_STATE_PATH), null, failingPersistence),
            new CoreSupportLifecycleParser(),
            Clock.fixed(VERIFIED_AT, ZoneOffset.UTC),
            100,
            "a".repeat(40),
            trust());

    boolean persisted = state.invalidateCompromisedUpdateKey();

    assertFalse(persisted);
    assertTrue(state.isUpdateKeyTrustInvalidated());
    assertFalse(state.snapshot().known());
    assertEquals(
        List.of("lifecycle_trust_invalidation_persistence_failed"), state.snapshot().warnings());
  }

  @Test
  void constructor_whenTrustInvalidationMarkerIsMalformed_expectTrustFailsClosed(
      @TempDir Path tempDir) throws Exception {
    Path descriptor = tempDir.resolve(LIFECYCLE_STATE_PATH);
    Files.createDirectories(tempDir.resolve("updates/core"));
    Files.writeString(
        descriptor.resolveSibling(descriptor.getFileName() + ".trust-invalidated"), "malformed");

    CoreSupportLifecycleState state = state(tempDir, RESTARTED_AT);
    byte[] fixture = CoreSupportLifecycleParserTest.fixtureBytes();

    assertTrue(state.isUpdateKeyTrustInvalidated());
    assertFalse(state.snapshot().known());
    assertEquals(
        List.of("lifecycle_trust_invalidation_marker_invalid"), state.snapshot().warnings());
    assertThrows(IllegalArgumentException.class, () -> state.accept(fixture, 1));
  }

  @Test
  void constructor_whenNodePathIsSymbolicLinkWithoutMarker_expectTrustRemainsValid(
      @TempDir Path tempDir) throws Exception {
    Path realNode = Files.createDirectory(tempDir.resolve("real-node"));
    Path configuredNode = tempDir.resolve("configured-node");
    Files.createSymbolicLink(configuredNode, realNode);

    CoreSupportLifecycleState state = state(configuredNode, RESTARTED_AT);

    assertFalse(state.isUpdateKeyTrustInvalidated());
    assertFalse(state.snapshot().known());
    assertEquals(List.of("lifecycle_persisted_state_invalid"), state.snapshot().warnings());
  }

  @Test
  void accept_whenNewDescriptorIsInvalid_expectLastKnownGoodRetained(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    state.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);
    byte[] invalid = "{}".getBytes(StandardCharsets.UTF_8);

    assertThrows(IllegalArgumentException.class, () -> state.accept(invalid, 2));

    assertTrue(state.snapshot().known());
    assertEquals(1, state.snapshot().descriptor().edition());
    assertEquals(ROOT_DIGEST, state.snapshot().descriptor().digest());
  }

  @Test
  void accept_whenEditionReplays_expectRollbackRejection(@TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] fixture = CoreSupportLifecycleParserTest.fixtureBytes();
    state.accept(fixture, 1);

    assertThrows(IllegalArgumentException.class, () -> state.accept(fixture, 1));
  }

  @Test
  void accept_whenFirstObservedDescriptorSkipsRootEdition_expectGapRejection(@TempDir Path tempDir)
      throws IOException {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] successor = successorBytes(null);

    assertThrows(IllegalArgumentException.class, () -> state.accept(successor, 2));

    assertFalse(state.snapshot().known());
  }

  @Test
  void accept_whenImmediateSemanticSuccessorArrives_expectEditionAdvances(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    state.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);
    byte[] successor = successorBytes(null);

    state.accept(successor, 2);

    assertEquals(2, state.snapshot().descriptor().edition());
    assertTrue(state.snapshot().known());
  }

  @Test
  void accept_whenSuccessorRewritesProductIdentity_expectLastKnownGoodRetained(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    state.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);
    byte[] successor = successorBytes(SHA_256_PREFIX + "6".repeat(64));

    assertThrows(IllegalArgumentException.class, () -> state.accept(successor, 2));

    assertEquals(1, state.snapshot().descriptor().edition());
  }

  @Test
  void snapshot_whenDescriptorHasPassedPolicyStaleAt_expectKnownButStale(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState accepted = state(tempDir, VERIFIED_AT);
    accepted.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);
    CoreSupportLifecycleState stale = state(tempDir, Instant.parse("2026-01-09T00:00:00Z"));

    CoreSupportLifecycleSnapshot snapshot = stale.snapshot();

    assertTrue(snapshot.known());
    assertTrue(snapshot.stale());
    assertTrue(snapshot.warnings().contains("lifecycle_descriptor_stale"));
  }

  @Test
  void snapshot_whenClockEqualsPolicyStaleAt_expectDescriptorIsStale(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState accepted = state(tempDir, VERIFIED_AT);
    accepted.accept(CoreSupportLifecycleParserTest.fixtureBytes(), 1);
    CoreSupportLifecycleState boundary = state(tempDir, Instant.parse("2026-01-08T00:00:00Z"));

    assertTrue(boundary.snapshot().stale());
  }

  @Test
  void snapshot_whenRunningTipIsRecoveryOnlyRevoked_expectRecoveryWithoutInventedBuild(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);

    state.accept(CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true), 1);

    CoreSupportLifecycleSnapshot snapshot = state.snapshot();
    assertEquals(REVOKED_STATUS, snapshot.running().status().wireValue());
    assertEquals(ACTIVE_RECOVERY_GUIDANCE, snapshot.running().recoveryGuidance());
    assertNull(snapshot.running().requiredReplacementBuild());
    assertNull(snapshot.recommendation().currentStableBuild());
    assertNull(snapshot.recommendation().recommendedBuild());
    assertFalse(snapshot.recommendation().upgradeAvailable());
  }

  @Test
  void isBuildRevoked_whenAcceptedEntryIsEffective_expectExactBuildBlocked(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    state.accept(CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true), 1);

    assertTrue(state.isBuildRevoked(100));
    assertFalse(state.isBuildRevoked(101));
  }

  @Test
  void snapshot_whenSuccessorActivationIsAheadOfClock_expectCandidateGuidanceHidden(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] current = CoreSupportLifecycleParserTest.fixtureBytes();
    state.accept(current, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();

    state.accept(futureEffectiveSuccessor(current, predecessorDigest), 2);

    CoreSupportLifecycleSnapshot snapshot = state.snapshot();
    assertFalse(snapshot.known());
    assertNull(snapshot.running().status());
    assertNull(snapshot.running().statusEffectiveAt());
    assertInactiveGuidanceHidden(snapshot);
    assertTrue(snapshot.warnings().contains("lifecycle_descriptor_not_effective"));
  }

  @Test
  void isBuildRevoked_whenEntryEffectiveTimeIsAheadOfClock_expectBuildNotYetBlocked(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, Instant.parse("2026-01-01T12:00:00Z"));

    state.accept(CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true), 1);

    assertFalse(state.isBuildRevoked(100));
  }

  @Test
  void isBuildRevoked_whenSuccessorActivationIsAheadOfClock_expectPriorRevocationRemainsBlocked(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(revoked, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();
    byte[] successor = futureEffectiveSuccessor(revoked, predecessorDigest);

    state.accept(successor, 2);
    CoreSupportLifecycleState restarted = state(tempDir, VERIFIED_AT);
    CoreSupportLifecycleState activated =
        state(tempDir, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT));

    assertEffectiveRevocationSnapshot(state.snapshot(), ACTIVE_RECOVERY_GUIDANCE);
    assertEffectiveRevocationSnapshot(restarted.snapshot(), ACTIVE_RECOVERY_GUIDANCE);
    assertEquals(FUTURE_RECOVERY_GUIDANCE, activated.snapshot().running().recoveryGuidance());
    assertTrue(state.isBuildRevoked(100));
    assertTrue(restarted.isBuildRevoked(100));
  }

  @Test
  void accept_whenTwoFutureSuccessorsArrive_expectEachGuidanceActivatesInOrder(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(revoked, 1);
    byte[] firstSuccessor =
        futureEffectiveSuccessor(revoked, state.snapshot().descriptor().digest());
    state.accept(firstSuccessor, 2);
    byte[] secondSuccessor =
        secondFutureEffectiveSuccessor(firstSuccessor, state.snapshot().descriptor().digest());

    CoreSupportLifecycleState.AcceptanceResult deferred = state.accept(secondSuccessor, 3);
    CoreSupportLifecycleState restarted = state(tempDir, VERIFIED_AT);
    CoreSupportLifecycleState firstSuccessorActivated =
        state(tempDir, Instant.parse("2026-01-03T12:00:00Z"));
    CoreSupportLifecycleState.AcceptanceResult accepted =
        firstSuccessorActivated.accept(secondSuccessor, 3);
    CoreSupportLifecycleState intervalRestarted =
        state(tempDir, Instant.parse("2026-01-03T12:00:00Z"));
    CoreSupportLifecycleState secondSuccessorActivated =
        state(tempDir, Instant.parse(SECOND_FUTURE_DESCRIPTOR_EFFECTIVE_AT));

    assertFalse(deferred.accepted());
    assertEquals(
        Duration.between(VERIFIED_AT, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT)).toMillis(),
        deferred.retryDelayMillis());
    assertEquals(2, state.acceptedEditionSeed());
    assertEffectiveRevocationSnapshot(state.snapshot(), ACTIVE_RECOVERY_GUIDANCE);
    assertEffectiveRevocationSnapshot(restarted.snapshot(), ACTIVE_RECOVERY_GUIDANCE);
    assertTrue(accepted.accepted());
    assertEquals(
        FUTURE_RECOVERY_GUIDANCE, firstSuccessorActivated.snapshot().running().recoveryGuidance());
    assertEquals(
        FUTURE_RECOVERY_GUIDANCE, intervalRestarted.snapshot().running().recoveryGuidance());
    assertEquals(
        SECOND_FUTURE_RECOVERY_GUIDANCE,
        secondSuccessorActivated.snapshot().running().recoveryGuidance());
  }

  @Test
  void snapshot_whenSecondSuccessorDescriptorRenameIsInterrupted_expectGuidanceRemainsBound(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(revoked, 1);
    byte[] firstSuccessor =
        futureEffectiveSuccessor(revoked, state.snapshot().descriptor().digest());
    state.accept(firstSuccessor, 2);
    Path descriptorPath = tempDir.resolve(LIFECYCLE_STATE_PATH);
    byte[] persistedFirstSuccessor = Files.readAllBytes(descriptorPath);
    byte[] secondSuccessor =
        secondFutureEffectiveSuccessor(firstSuccessor, state.snapshot().descriptor().digest());
    CoreSupportLifecycleState ready = state(tempDir, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT));
    ready.accept(secondSuccessor, 3);
    Files.write(descriptorPath, persistedFirstSuccessor);

    CoreSupportLifecycleState interrupted =
        state(tempDir, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT));
    interrupted.accept(secondSuccessor, 3);
    CoreSupportLifecycleState restarted =
        state(tempDir, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT));

    assertEffectiveRevocationSnapshot(interrupted.snapshot(), FUTURE_RECOVERY_GUIDANCE);
    assertEffectiveRevocationSnapshot(restarted.snapshot(), FUTURE_RECOVERY_GUIDANCE);
  }

  @Test
  void snapshot_whenVersionTwoProjectionIsRestored_expectGuidanceRemainsCompatible(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(revoked, 1);
    state.accept(futureEffectiveSuccessor(revoked, state.snapshot().descriptor().digest()), 2);
    downgradeRevocationProjectionToVersionTwo(tempDir);

    CoreSupportLifecycleState restarted = state(tempDir, VERIFIED_AT);

    assertEffectiveRevocationSnapshot(restarted.snapshot(), ACTIVE_RECOVERY_GUIDANCE);
  }

  @Test
  void snapshot_whenActiveRevocationReplacementChanges_expectPriorReplacementPreserved(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = revocationWithReplacementDescriptor();
    state.accept(revoked, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();

    state.accept(futureEffectiveSuccessorWithReplacement(revoked, predecessorDigest), 2);
    CoreSupportLifecycleState restarted = state(tempDir, VERIFIED_AT);
    CoreSupportLifecycleState activated =
        state(tempDir, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT));

    assertEquals(101, state.snapshot().running().requiredReplacementBuild());
    assertEquals(101, restarted.snapshot().running().requiredReplacementBuild());
    assertNull(state.snapshot().running().recoveryGuidance());
    assertEquals(101, activated.snapshot().running().requiredReplacementBuild());
  }

  @Test
  void isBuildRevoked_whenPriorRevocationStateIsMissing_expectRestartFailsClosed(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(revoked, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();
    state.accept(futureEffectiveSuccessor(revoked, predecessorDigest), 2);
    Files.delete(revocationStatePath(tempDir));

    CoreSupportLifecycleState restarted = state(tempDir, VERIFIED_AT);

    assertEffectiveRevocationSnapshot(restarted.snapshot(), null);
    assertTrue(restarted.isBuildRevoked(100));
  }

  @Test
  void isBuildRevoked_whenPriorRevocationStateIsInvalid_expectRestartFailsClosed(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(revoked, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();
    state.accept(futureEffectiveSuccessor(revoked, predecessorDigest), 2);
    Files.writeString(revocationStatePath(tempDir), "{}");

    CoreSupportLifecycleState restarted = state(tempDir, VERIFIED_AT);

    assertEffectiveRevocationSnapshot(restarted.snapshot(), null);
    assertTrue(restarted.isBuildRevoked(100));
  }

  @Test
  void snapshot_whenRecoveryProjectionBindsWrongPredecessor_expectGuidanceWithheld(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] revoked = CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true);
    state.accept(revoked, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();
    state.accept(futureEffectiveSuccessor(revoked, predecessorDigest), 2);
    corruptProjectionPredecessorDigest(tempDir);

    CoreSupportLifecycleState restarted = state(tempDir, VERIFIED_AT);

    assertEffectiveRevocationSnapshot(restarted.snapshot(), null);
    assertTrue(restarted.isBuildRevoked(100));
  }

  @Test
  void isBuildRevoked_whenFutureSuccessorIntroducesRevocation_expectActivationGatePreserved(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] previous = CoreSupportLifecycleParserTest.fixtureBytes();
    state.accept(previous, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();
    byte[] successor = futureEffectiveRevocationSuccessor(previous, predecessorDigest);

    state.accept(successor, 2);
    CoreSupportLifecycleState restartedBeforeActivation = state(tempDir, VERIFIED_AT);
    CoreSupportLifecycleState restartedAfterActivation =
        state(tempDir, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT));

    assertFalse(state.snapshot().known());
    assertFalse(state.snapshot().warnings().contains(BUILD_REVOKED_WARNING));
    assertFalse(state.isBuildRevoked(100));
    assertFalse(restartedBeforeActivation.isBuildRevoked(100));
    assertTrue(restartedAfterActivation.isBuildRevoked(100));
  }

  @Test
  void pendingBuildRevocationDelay_whenFutureSuccessorIntroducesRevocation_expectActivationDelay(
      @TempDir Path tempDir) throws Exception {
    CoreSupportLifecycleState state = state(tempDir, VERIFIED_AT);
    byte[] previous = CoreSupportLifecycleParserTest.fixtureBytes();
    state.accept(previous, 1);
    String predecessorDigest = state.snapshot().descriptor().digest();

    state.accept(futureEffectiveRevocationSuccessor(previous, predecessorDigest), 2);

    assertEquals(
        Duration.between(VERIFIED_AT, Instant.parse(FUTURE_DESCRIPTOR_EFFECTIVE_AT)).toMillis(),
        state.pendingBuildRevocationDelayMillis(100).orElseThrow());
    assertTrue(state.pendingBuildRevocationDelayMillis(101).isEmpty());
  }

  private static CoreSupportLifecycleState state(Path tempDir, Instant now) {
    return state(tempDir, now, "a".repeat(40));
  }

  private static void assertEffectiveRevocationSnapshot(
      CoreSupportLifecycleSnapshot snapshot, String expectedRecoveryGuidance) {
    assertTrue(snapshot.known());
    assertEquals(REVOKED_STATUS, snapshot.running().status().wireValue());
    assertEquals(REVOCATION_EFFECTIVE_AT, snapshot.running().statusEffectiveAt());
    assertNull(snapshot.running().fullSupportUntil());
    assertNull(snapshot.running().securityFixesUntil());
    assertNull(snapshot.running().deprecationEffectiveAt());
    assertNull(snapshot.running().endOfSupportAt());
    assertNull(snapshot.running().requiredReplacementBuild());
    assertEquals(expectedRecoveryGuidance, snapshot.running().recoveryGuidance());
    assertEquals(List.of(SECURITY_ADVISORY_ID), snapshot.running().advisoryIds());
    assertEquals(List.of(REVOCATION_REASON_CODE), snapshot.running().reasonCodes());
    assertRecommendationHidden(snapshot);
    assertTrue(snapshot.warnings().contains(BUILD_REVOKED_WARNING));
    assertTrue(snapshot.warnings().contains("lifecycle_descriptor_not_effective"));
  }

  private static void assertInactiveGuidanceHidden(CoreSupportLifecycleSnapshot snapshot) {
    assertNull(snapshot.running().fullSupportUntil());
    assertNull(snapshot.running().securityFixesUntil());
    assertNull(snapshot.running().deprecationEffectiveAt());
    assertNull(snapshot.running().endOfSupportAt());
    assertNull(snapshot.running().requiredReplacementBuild());
    assertNull(snapshot.running().recoveryGuidance());
    assertTrue(snapshot.running().advisoryIds().isEmpty());
    assertTrue(snapshot.running().reasonCodes().isEmpty());
    assertRecommendationHidden(snapshot);
  }

  private static void assertRecommendationHidden(CoreSupportLifecycleSnapshot snapshot) {
    assertNull(snapshot.recommendation().currentStableBuild());
    assertNull(snapshot.recommendation().recommendedBuild());
    assertFalse(snapshot.recommendation().upgradeAvailable());
  }

  private static Path revocationStatePath(Path tempDir) {
    Path descriptor = tempDir.resolve(LIFECYCLE_STATE_PATH);
    return descriptor.resolveSibling(descriptor.getFileName() + REVOCATION_STATE_SUFFIX);
  }

  private static void corruptProjectionPredecessorDigest(Path tempDir) throws IOException {
    Path statePath = revocationStatePath(tempDir);
    Map<String, Object> state = JsonMini.parseObject(Files.readString(statePath));
    @SuppressWarnings("unchecked")
    Map<String, Object> projection = (Map<String, Object>) state.get("runningRevocationProjection");
    projection.put("sourceDescriptorDigest", SHA_256_PREFIX + "f".repeat(64));
    Files.writeString(statePath, CoreSupportLifecycleParser.canonicalJson(state));
  }

  private static void downgradeRevocationProjectionToVersionTwo(Path tempDir) throws IOException {
    Path statePath = revocationStatePath(tempDir);
    Map<String, Object> state = JsonMini.parseObject(Files.readString(statePath));
    state.put("schemaVersion", 2L);
    @SuppressWarnings("unchecked")
    Map<String, Object> projection = (Map<String, Object>) state.get("runningRevocationProjection");
    projection.remove("targetDescriptorDigest");
    Files.writeString(statePath, CoreSupportLifecycleParser.canonicalJson(state));
  }

  private static CoreSupportLifecycleState state(
      Path tempDir, Instant now, String runningSourceCommit) {
    return new CoreSupportLifecycleState(
        new CoreSupportLifecycleStore(tempDir.resolve(LIFECYCLE_STATE_PATH)),
        new CoreSupportLifecycleParser(),
        Clock.fixed(now, ZoneOffset.UTC),
        100,
        runningSourceCommit,
        trust());
  }

  private static CoreSupportLifecycleParser.TrustBinding trust() {
    return new CoreSupportLifecycleParser.TrustBinding(
        IDENTITY_DIGEST, IDENTITY_DIGEST + "/support-lifecycle/0", "support-lifecycle");
  }

  private static byte[] successorBytes(String replacementProductDigest) throws IOException {
    String successor =
        CoreSupportLifecycleParserTest.fixtureText()
            .replace("\"descriptorEdition\": 1", "\"descriptorEdition\": 2")
            .replace(
                "\"previousDescriptorDigest\": null",
                "\"previousDescriptorDigest\": \"" + ROOT_DIGEST + "\"")
            .replace("\"previousDescriptorEdition\": null", "\"previousDescriptorEdition\": 1");
    if (replacementProductDigest != null) {
      successor = successor.replace(SHA_256_PREFIX + "3".repeat(64), replacementProductDigest);
    }
    Map<String, Object> root = JsonMini.parseObject(successor);
    root.remove(DESCRIPTOR_DIGEST_FIELD);
    String digest = CoreSupportLifecycleParser.semanticDigest(root);
    successor =
        successor.replace(
            "\"descriptorDigest\": \"" + ROOT_DIGEST + "\"",
            "\"descriptorDigest\": \"" + digest + "\"");
    return successor.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] futureEffectiveSuccessor(byte[] previous, String previousDigest) {
    return futureEffectiveSuccessor(
        previous,
        previousDigest,
        new FutureSuccessorFixture(
            2L,
            1L,
            "2026-01-02T06:00:00Z",
            FUTURE_DESCRIPTOR_EFFECTIVE_AT,
            "2026-01-10T00:00:00Z",
            FUTURE_RECOVERY_GUIDANCE));
  }

  private static byte[] secondFutureEffectiveSuccessor(byte[] previous, String previousDigest) {
    return futureEffectiveSuccessor(
        previous,
        previousDigest,
        new FutureSuccessorFixture(
            3L,
            2L,
            "2026-01-02T07:00:00Z",
            SECOND_FUTURE_DESCRIPTOR_EFFECTIVE_AT,
            "2026-01-11T00:00:00Z",
            SECOND_FUTURE_RECOVERY_GUIDANCE));
  }

  private static byte[] futureEffectiveSuccessor(
      byte[] previous, String previousDigest, FutureSuccessorFixture fixture) {
    Map<String, Object> root = JsonMini.parseObject(new String(previous, StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    Map<String, Object> entry =
        (Map<String, Object>) ((List<?>) root.get(ENTRIES_FIELD)).getFirst();
    if (REVOKED_STATUS.equals(entry.get("lifecycleStatus"))) {
      entry.put(REPLACEMENT_BUILD_FIELD, null);
      entry.put(RECOVERY_GUIDANCE_FIELD, fixture.recoveryGuidance());
    }
    root.put("generatedAt", fixture.generatedAt());
    root.put("effectiveAt", fixture.effectiveAt());
    root.put("staleAt", fixture.staleAt());
    root.put("descriptorEdition", fixture.descriptorEdition());
    root.put("previousDescriptorEdition", fixture.previousDescriptorEdition());
    root.put("previousDescriptorDigest", previousDigest);
    root.remove(DESCRIPTOR_DIGEST_FIELD);
    root.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(root));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }

  private record FutureSuccessorFixture(
      long descriptorEdition,
      long previousDescriptorEdition,
      String generatedAt,
      String effectiveAt,
      String staleAt,
      String recoveryGuidance) {}

  private static byte[] revocationWithReplacementDescriptor() throws IOException {
    Map<String, Object> root =
        JsonMini.parseObject(
            new String(
                CoreSupportLifecycleParserTest.emergencyRevocationDescriptor(false, true),
                StandardCharsets.UTF_8));
    Map<String, Object> fixture =
        JsonMini.parseObject(
            new String(CoreSupportLifecycleParserTest.fixtureBytes(), StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    Map<String, Object> revoked =
        (Map<String, Object>) ((List<?>) root.get(ENTRIES_FIELD)).getFirst();
    @SuppressWarnings("unchecked")
    Map<String, Object> template =
        (Map<String, Object>) ((List<?>) fixture.get(ENTRIES_FIELD)).getFirst();
    Map<String, Object> replacement = replacementEntry(template);
    revoked.put(REPLACEMENT_BUILD_FIELD, "101");
    revoked.put(RECOVERY_GUIDANCE_FIELD, null);
    root.put(ENTRIES_FIELD, List.of(revoked, replacement));
    root.put("currentStableBuild", "101");
    root.put("minimumSupportedBuild", "101");
    root.put("minimumSecuritySupportedBuild", "101");
    root.put("recommendedBuild", "101");
    root.remove(DESCRIPTOR_DIGEST_FIELD);
    root.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(root));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }

  private static Map<String, Object> replacementEntry(Map<String, Object> template) {
    Map<String, Object> replacement = new LinkedHashMap<>(template);
    replacement.put("releaseId", "stable-1.0-maintenance-v101");
    replacement.put("buildVersion", "101");
    replacement.put("tag", "v101");
    replacement.put("sourceCommit", "b".repeat(40));
    replacement.put("productDigest", SHA_256_PREFIX + "6".repeat(64));
    replacement.put("publicationReceiptDigest", SHA_256_PREFIX + "7".repeat(64));
    replacement.put("baselineDigest", SHA_256_PREFIX + "8".repeat(64));
    replacement.put("publishedAt", REVOCATION_EFFECTIVE_AT);
    replacement.put("statusEffectiveAt", REVOCATION_EFFECTIVE_AT);
    return replacement;
  }

  private static byte[] futureEffectiveSuccessorWithReplacement(
      byte[] previous, String previousDigest) {
    Map<String, Object> root =
        JsonMini.parseObject(
            new String(futureEffectiveSuccessor(previous, previousDigest), StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    Map<String, Object> revoked =
        (Map<String, Object>) ((List<?>) root.get(ENTRIES_FIELD)).getFirst();
    revoked.put(REPLACEMENT_BUILD_FIELD, "101");
    revoked.put(RECOVERY_GUIDANCE_FIELD, null);
    root.remove(DESCRIPTOR_DIGEST_FIELD);
    root.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(root));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] futureEffectiveRevocationSuccessor(byte[] previous, String previousDigest) {
    Map<String, Object> root = JsonMini.parseObject(new String(previous, StandardCharsets.UTF_8));
    @SuppressWarnings("unchecked")
    Map<String, Object> entry =
        (Map<String, Object>) ((List<?>) root.get(ENTRIES_FIELD)).getFirst();
    entry.put("lifecycleStatus", REVOKED_STATUS);
    entry.put("statusEffectiveAt", REVOCATION_EFFECTIVE_AT);
    entry.put("securityRevocationEffectiveAt", REVOCATION_EFFECTIVE_AT);
    entry.put(REPLACEMENT_BUILD_FIELD, null);
    entry.put(RECOVERY_GUIDANCE_FIELD, ACTIVE_RECOVERY_GUIDANCE);
    entry.put("advisoryIds", List.of(SECURITY_ADVISORY_ID));
    entry.put("reasonCodes", List.of(REVOCATION_REASON_CODE));
    root.put("generatedAt", "2026-01-02T06:00:00Z");
    root.put("effectiveAt", FUTURE_DESCRIPTOR_EFFECTIVE_AT);
    root.put("staleAt", "2026-01-10T00:00:00Z");
    root.put("descriptorEdition", 2L);
    root.put("previousDescriptorEdition", 1L);
    root.put("previousDescriptorDigest", previousDigest);
    root.put("currentStableBuild", null);
    root.put("recommendedBuild", null);
    root.put("minimumSupportedBuild", null);
    root.put("minimumSecuritySupportedBuild", null);
    root.remove(DESCRIPTOR_DIGEST_FIELD);
    root.put(DESCRIPTOR_DIGEST_FIELD, CoreSupportLifecycleParser.semanticDigest(root));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }
}
