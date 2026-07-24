package network.crypta.runtime.updater;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
  private static final String LIFECYCLE_STATE_PATH = "updates/core/lifecycle.json";

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
    assertEquals("revoked", snapshot.running().status().wireValue());
    assertEquals(
        "Restore from a verified backup and wait for an authenticated replacement.",
        snapshot.running().recoveryGuidance());
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

    assertFalse(state.snapshot().known());
    assertTrue(state.isBuildRevoked(100));
    assertTrue(restarted.isBuildRevoked(100));
  }

  private static CoreSupportLifecycleState state(Path tempDir, Instant now) {
    return state(tempDir, now, "a".repeat(40));
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
    root.remove("descriptorDigest");
    String digest = CoreSupportLifecycleParser.semanticDigest(root);
    successor =
        successor.replace(
            "\"descriptorDigest\": \"" + ROOT_DIGEST + "\"",
            "\"descriptorDigest\": \"" + digest + "\"");
    return successor.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] futureEffectiveSuccessor(byte[] previous, String previousDigest) {
    Map<String, Object> root = JsonMini.parseObject(new String(previous, StandardCharsets.UTF_8));
    root.put("generatedAt", "2026-01-02T06:00:00Z");
    root.put("effectiveAt", "2026-01-03T00:00:00Z");
    root.put("staleAt", "2026-01-10T00:00:00Z");
    root.put("descriptorEdition", 2L);
    root.put("previousDescriptorEdition", 1L);
    root.put("previousDescriptorDigest", previousDigest);
    root.remove("descriptorDigest");
    root.put("descriptorDigest", CoreSupportLifecycleParser.semanticDigest(root));
    return CoreSupportLifecycleParser.canonicalJson(root).getBytes(StandardCharsets.UTF_8);
  }
}
