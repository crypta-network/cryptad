package network.crypta.runtime.updater;

import com.sun.jna.platform.win32.WinBase;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CoreSupportLifecycleStoreTest {
  private static final String DESCRIPTOR_PATH = "updates/core/lifecycle.json";
  private static final String FALLBACK_MARKER_PATH = "update-key-trust-invalidated";
  private static final String REAL_NODE_DIRECTORY = "real-node";
  private static final String CONFIGURED_NODE_DIRECTORY = "configured-node";
  private static final String PUBLISH_REPLACE = "publish-replace";
  private static final Instant VERIFIED_AT = Instant.parse("2026-01-02T12:00:00Z");
  private static final Instant LATER_VERIFIED_AT = Instant.parse("2026-01-03T12:00:00Z");

  @Test
  void saveAndLoad_whenPathIsRegular_expectExactBytesAndVerificationTime(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(tempDir.resolve(DESCRIPTOR_PATH));
    byte[] bytes = CoreSupportLifecycleParserTest.fixtureBytes();
    Instant verifiedAt = VERIFIED_AT;

    store.save(bytes, verifiedAt);
    CoreSupportLifecycleStore.StoredDescriptor stored = store.load();

    assertNotNull(stored);
    assertEquals(
        CoreSupportLifecycleParser.exactBytesDigest(bytes),
        CoreSupportLifecycleParser.exactBytesDigest(stored.bytes()));
    assertEquals(verifiedAt, stored.verifiedAt());
    assertEquals(0, stored.revocationState().length);
  }

  @Test
  void save_whenPublishingDescriptor_expectFileForcedBeforeCommit(@TempDir Path tempDir)
      throws Exception {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    RecordingPersistenceSync persistenceSync = new RecordingPersistenceSync();
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(descriptor, null, persistenceSync);

    store.save(CoreSupportLifecycleParserTest.fixtureBytes(), VERIFIED_AT);

    assertEquals(2, persistenceSync.events.size());
    assertEquals("file", persistenceSync.events.get(0).operation());
    assertTrue(
        Objects.requireNonNull(persistenceSync.events.get(0).path().getFileName())
            .toString()
            .startsWith(".support-lifecycle-"));
    assertEquals(new SyncEvent(PUBLISH_REPLACE, descriptor), persistenceSync.events.get(1));
  }

  @Test
  void save_whenPublishingRevocationState_expectStateIsDurableBeforeDescriptor(
      @TempDir Path tempDir) throws Exception {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    Path revocationState =
        descriptor.resolveSibling(descriptor.getFileName() + ".revocation-activations");
    byte[] metadata = "{\"schemaVersion\":1}".getBytes(StandardCharsets.UTF_8);
    RecordingPersistenceSync persistenceSync = new RecordingPersistenceSync();
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(descriptor, null, persistenceSync);

    store.save(CoreSupportLifecycleParserTest.fixtureBytes(), VERIFIED_AT, metadata);
    CoreSupportLifecycleStore.StoredDescriptor stored = store.load();

    assertNotNull(stored);
    assertEquals(
        CoreSupportLifecycleParser.exactBytesDigest(metadata),
        CoreSupportLifecycleParser.exactBytesDigest(stored.revocationState()));
    assertEquals(4, persistenceSync.events.size());
    assertTrue(
        Objects.requireNonNull(persistenceSync.events.get(0).path().getFileName())
            .toString()
            .startsWith(".support-lifecycle-revocations-"));
    assertEquals(new SyncEvent(PUBLISH_REPLACE, revocationState), persistenceSync.events.get(1));
    assertEquals(new SyncEvent(PUBLISH_REPLACE, descriptor), persistenceSync.events.get(3));
  }

  @Test
  void save_whenStatePublicationFails_expectPersistenceFailure(@TempDir Path tempDir) {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    RecordingPersistenceSync persistenceSync = new RecordingPersistenceSync();
    persistenceSync.failPublication = true;
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(descriptor, null, persistenceSync);

    assertThrows(
        IOException.class,
        () -> store.save(CoreSupportLifecycleParserTest.fixtureBytes(), VERIFIED_AT));
  }

  @Test
  void save_whenControlledDescendantIsSymbolicLink_expectRejection(@TempDir Path tempDir)
      throws Exception {
    Path nodeRoot = Files.createDirectory(tempDir.resolve("node"));
    Path outside = Files.createDirectory(tempDir.resolve("outside"));
    Files.createSymbolicLink(nodeRoot.resolve("updates"), outside);
    CoreSupportLifecycleStore store =
        CoreSupportLifecycleStore.underAcceptedRoot(
            nodeRoot, Path.of(DESCRIPTOR_PATH), Path.of(FALLBACK_MARKER_PATH));

    assertThrows(
        IOException.class,
        () -> store.save(CoreSupportLifecycleParserTest.fixtureBytes(), VERIFIED_AT));
  }

  @Test
  void saveAndLoad_whenAcceptedRootIsSymbolicLink_expectPersistenceUsesPinnedTarget(
      @TempDir Path tempDir) throws Exception {
    Path realNode = Files.createDirectory(tempDir.resolve(REAL_NODE_DIRECTORY));
    Path redirectedNode = Files.createDirectory(tempDir.resolve("redirected-node"));
    Path configuredNode = tempDir.resolve(CONFIGURED_NODE_DIRECTORY);
    Files.createSymbolicLink(configuredNode, realNode);
    CoreSupportLifecycleStore store =
        CoreSupportLifecycleStore.underAcceptedRoot(
            configuredNode, Path.of(DESCRIPTOR_PATH), Path.of(FALLBACK_MARKER_PATH));
    byte[] descriptor = CoreSupportLifecycleParserTest.fixtureBytes();
    Files.delete(configuredNode);
    Files.createSymbolicLink(configuredNode, redirectedNode);

    store.save(descriptor, VERIFIED_AT);
    CoreSupportLifecycleStore.StoredDescriptor stored = store.load();

    assertNotNull(stored);
    assertEquals(
        CoreSupportLifecycleParser.exactBytesDigest(descriptor),
        CoreSupportLifecycleParser.exactBytesDigest(stored.bytes()));
    assertTrue(Files.isRegularFile(realNode.resolve(DESCRIPTOR_PATH)));
    assertFalse(Files.exists(redirectedNode.resolve(DESCRIPTOR_PATH)));
  }

  @Test
  void invalidateTrust_whenAcceptedRootIsSymbolicLink_expectBothMarkersAreDurable(
      @TempDir Path tempDir) throws Exception {
    Path realNode = Files.createDirectory(tempDir.resolve(REAL_NODE_DIRECTORY));
    Path configuredNode = tempDir.resolve(CONFIGURED_NODE_DIRECTORY);
    Files.createSymbolicLink(configuredNode, realNode);
    CoreSupportLifecycleStore store =
        CoreSupportLifecycleStore.underAcceptedRoot(
            configuredNode, Path.of(DESCRIPTOR_PATH), Path.of(FALLBACK_MARKER_PATH));
    Path descriptor = realNode.resolve(DESCRIPTOR_PATH);
    store.save(CoreSupportLifecycleParserTest.fixtureBytes(), VERIFIED_AT);

    store.invalidateTrust();

    assertTrue(Files.isRegularFile(invalidationMarker(descriptor)));
    assertTrue(Files.isRegularFile(realNode.resolve(FALLBACK_MARKER_PATH)));
    assertTrue(store.isTrustInvalidated());
    assertNull(store.load());
  }

  @Test
  void underAcceptedRoot_whenRelativePathEscapes_expectRejection(@TempDir Path tempDir)
      throws Exception {
    Path nodeRoot = Files.createDirectory(tempDir.resolve("node"));
    Path escaped = Path.of("..", "outside.json");

    assertThrows(
        IOException.class,
        () -> CoreSupportLifecycleStore.underAcceptedRoot(nodeRoot, escaped, null));
  }

  @Test
  void trustInvalidationStatus_whenAncestorIsSymbolicLinkAndMarkerIsAbsent_expectAbsent(
      @TempDir Path tempDir) throws Exception {
    Path real = Files.createDirectory(tempDir.resolve(REAL_NODE_DIRECTORY));
    Path configuredNode = tempDir.resolve(CONFIGURED_NODE_DIRECTORY);
    Files.createSymbolicLink(configuredNode, real);
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(configuredNode.resolve(DESCRIPTOR_PATH));

    assertEquals(
        CoreSupportLifecycleStore.TrustInvalidationStatus.ABSENT, store.trustInvalidationStatus());
    assertFalse(store.isTrustInvalidated());
  }

  @Test
  void invalidateTrust_whenDescriptorExists_expectPersistedStateCannotReload(@TempDir Path tempDir)
      throws Exception {
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(tempDir.resolve(DESCRIPTOR_PATH));
    byte[] bytes = CoreSupportLifecycleParserTest.fixtureBytes();
    store.save(bytes, VERIFIED_AT);

    store.invalidateTrust();
    Files.write(tempDir.resolve(DESCRIPTOR_PATH), bytes);

    assertNull(store.load());
    assertTrue(store.isTrustInvalidated());
    assertThrows(
        IOException.class,
        () -> store.save(CoreSupportLifecycleParserTest.fixtureBytes(), LATER_VERIFIED_AT));
  }

  @Test
  void invalidateTrust_whenPublishingMarker_expectFileForcedBeforeCommit(@TempDir Path tempDir)
      throws Exception {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    RecordingPersistenceSync persistenceSync = new RecordingPersistenceSync();
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(descriptor, null, persistenceSync);

    store.invalidateTrust();

    assertEquals(2, persistenceSync.events.size());
    assertEquals("file", persistenceSync.events.get(0).operation());
    assertTrue(
        Objects.requireNonNull(persistenceSync.events.get(0).path().getFileName())
            .toString()
            .startsWith(".support-lifecycle-invalidation-"));
    assertEquals(
        new SyncEvent("publish-new", invalidationMarker(descriptor)),
        persistenceSync.events.get(1));
  }

  @Test
  void invalidateTrust_whenMarkerPublicationFails_expectNoDurableSuccess(@TempDir Path tempDir) {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    RecordingPersistenceSync persistenceSync = new RecordingPersistenceSync();
    persistenceSync.failPublication = true;
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(descriptor, null, persistenceSync);

    assertThrows(IOException.class, store::invalidateTrust);
    assertFalse(Files.isRegularFile(descriptor));
  }

  @Test
  void invalidateTrust_whenMarkerAlreadyExists_expectDurableReplacement(@TempDir Path tempDir)
      throws Exception {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    RecordingPersistenceSync persistenceSync = new RecordingPersistenceSync();
    CoreSupportLifecycleStore store =
        new CoreSupportLifecycleStore(descriptor, null, persistenceSync);
    store.invalidateTrust();
    persistenceSync.events.clear();

    store.invalidateTrust();

    assertEquals(2, persistenceSync.events.size());
    assertEquals("file", persistenceSync.events.get(0).operation());
    assertEquals(
        new SyncEvent(PUBLISH_REPLACE, invalidationMarker(descriptor)),
        persistenceSync.events.get(1));
  }

  @Test
  void persistenceSyncFor_whenWindows_expectWriteThroughNativeMove(@TempDir Path tempDir)
      throws Exception {
    RecordingWindowsMove windowsMove = new RecordingWindowsMove();
    CoreSupportLifecycleStore.PersistenceSync persistenceSync =
        CoreSupportLifecycleStore.persistenceSyncFor(true, windowsMove);
    Path temporary = tempDir.resolve("descriptor.tmp");
    Path target = tempDir.resolve("descriptor.json");

    persistenceSync.publish(temporary, target, true);

    assertEquals(temporary.toString(), windowsMove.source);
    assertEquals(target.toString(), windowsMove.target);
    assertEquals(
        WinBase.MOVEFILE_WRITE_THROUGH | WinBase.MOVEFILE_REPLACE_EXISTING, windowsMove.flags);
  }

  @Test
  void persistenceSyncFor_whenWindowsMarkerIsNew_expectWriteThroughWithoutReplacement(
      @TempDir Path tempDir) throws Exception {
    RecordingWindowsMove windowsMove = new RecordingWindowsMove();
    CoreSupportLifecycleStore.PersistenceSync persistenceSync =
        CoreSupportLifecycleStore.persistenceSyncFor(true, windowsMove);
    Path temporary = tempDir.resolve("marker.tmp");
    Path target = tempDir.resolve("marker");

    persistenceSync.publish(temporary, target, false);

    assertEquals(WinBase.MOVEFILE_WRITE_THROUGH, windowsMove.flags);
  }

  @Test
  void persistenceSyncFor_whenWindowsMoveFails_expectOperatingSystemError(@TempDir Path tempDir) {
    RecordingWindowsMove windowsMove = new RecordingWindowsMove();
    windowsMove.succeed = false;
    windowsMove.error = 5;
    CoreSupportLifecycleStore.PersistenceSync persistenceSync =
        CoreSupportLifecycleStore.persistenceSyncFor(true, windowsMove);

    IOException error =
        assertThrows(
            IOException.class,
            () ->
                persistenceSync.publish(
                    tempDir.resolve("descriptor.tmp"), tempDir.resolve("descriptor.json"), true));

    assertTrue(error.getMessage().contains("operating-system error 5"));
  }

  @Test
  void invalidateTrust_whenSiblingMarkerConflicts_expectFallbackSurvivesRecovery(
      @TempDir Path tempDir) throws Exception {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    Path fallback = tempDir.resolve(FALLBACK_MARKER_PATH);
    CoreSupportLifecycleStore store = new CoreSupportLifecycleStore(descriptor, fallback);
    byte[] bytes = CoreSupportLifecycleParserTest.fixtureBytes();
    store.save(bytes, VERIFIED_AT);
    Path siblingMarker = invalidationMarker(descriptor);
    Files.createDirectory(siblingMarker);

    store.invalidateTrust();
    Files.delete(siblingMarker);
    Files.write(descriptor, bytes);
    CoreSupportLifecycleStore restarted = new CoreSupportLifecycleStore(descriptor, fallback);

    assertTrue(Files.isRegularFile(fallback));
    assertTrue(restarted.isTrustInvalidated());
    assertEquals(
        CoreSupportLifecycleStore.TrustInvalidationStatus.VALID,
        restarted.trustInvalidationStatus());
    assertNull(restarted.load());
  }

  @Test
  void isTrustInvalidated_whenMarkerIsSymbolicLink_expectFailClosed(@TempDir Path tempDir)
      throws Exception {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    Files.createDirectories(tempDir.resolve("updates/core"));
    Path markerTarget = Files.writeString(tempDir.resolve("outside-marker"), "untrusted");
    Files.createSymbolicLink(invalidationMarker(descriptor), markerTarget);
    CoreSupportLifecycleStore store = new CoreSupportLifecycleStore(descriptor);

    assertTrue(store.isTrustInvalidated());
    assertEquals(
        CoreSupportLifecycleStore.TrustInvalidationStatus.INVALID, store.trustInvalidationStatus());
    assertNull(store.load());
    assertThrows(
        IOException.class,
        () -> store.save(CoreSupportLifecycleParserTest.fixtureBytes(), LATER_VERIFIED_AT));
  }

  @Test
  void isTrustInvalidated_whenMarkerIsMalformed_expectFailClosed(@TempDir Path tempDir)
      throws Exception {
    Path descriptor = tempDir.resolve(DESCRIPTOR_PATH);
    Files.createDirectories(tempDir.resolve("updates/core"));
    Files.writeString(invalidationMarker(descriptor), "malformed");
    CoreSupportLifecycleStore store = new CoreSupportLifecycleStore(descriptor);

    assertTrue(store.isTrustInvalidated());
    assertEquals(
        CoreSupportLifecycleStore.TrustInvalidationStatus.INVALID, store.trustInvalidationStatus());
    assertNull(store.load());
    assertThrows(
        IOException.class,
        () -> store.save(CoreSupportLifecycleParserTest.fixtureBytes(), LATER_VERIFIED_AT));
  }

  private static Path invalidationMarker(Path descriptor) {
    return descriptor.resolveSibling(descriptor.getFileName() + ".trust-invalidated");
  }

  private static final class RecordingPersistenceSync
      implements CoreSupportLifecycleStore.PersistenceSync {
    private final List<SyncEvent> events = new ArrayList<>();
    private boolean failPublication;

    @Override
    public void forceFile(Path file) {
      events.add(new SyncEvent("file", file));
    }

    @Override
    public void publish(Path temporary, Path target, boolean replaceExisting) throws IOException {
      events.add(new SyncEvent(replaceExisting ? PUBLISH_REPLACE : "publish-new", target));
      if (failPublication) {
        throw new IOException("simulated state publication failure");
      }
      if (replaceExisting) {
        Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
      } else {
        Files.move(temporary, target);
      }
    }
  }

  private static final class RecordingWindowsMove implements CoreSupportLifecycleStore.WindowsMove {
    private String source;
    private String target;
    private int flags;
    private boolean succeed = true;
    private int error;

    @Override
    public boolean move(String source, String target, int flags) {
      this.source = source;
      this.target = target;
      this.flags = flags;
      return succeed;
    }

    @Override
    public int lastError() {
      return error;
    }
  }

  private record SyncEvent(String operation, Path path) {}
}
