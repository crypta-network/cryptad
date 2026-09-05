package network.crypta.platform.apphost.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifiedInstalledBundleGuardTest {
  private static final String APP_ID = "site-publisher";
  private static final String KEY_ID = "test-migration-guard";

  @TempDir Path temporary;

  @Test
  void withVerifiedInstalledBundle_whenSigned_expectAuthenticatedExactIdentity() throws Exception {
    KeyPair signer = signer();
    LocalProcessAppHost host = signedHost(signer);
    Path bundle = signedBundle("1", signer);
    InstalledAppSnapshot installed = host.installFromDirectory(bundle);
    AppBundleVerification expected =
        AppBundleVerifier.requireSigned(trustedKeys(signer)).verify(bundle);

    AppBundleVerification actual =
        host.withVerifiedInstalledBundle(
            APP_ID,
            (snapshot, verification) -> {
              assertEquals(installed.manifest(), snapshot.manifest());
              return verification;
            });

    assertTrue(actual.signed());
    assertEquals(expected.keyFingerprintSha256(), actual.keyFingerprintSha256());
    assertEquals(expected.signedContentDigestSha256(), actual.signedContentDigestSha256());
  }

  @Test
  void withVerifiedInstalledBundle_whenUnsignedDevelopmentApp_expectActionNeverRuns()
      throws Exception {
    LocalProcessAppHost host =
        new LocalProcessAppHost(
            layout(), AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());
    host.installFromDirectory(bundle("1"));
    AtomicBoolean actionRan = new AtomicBoolean();

    assertThrows(
        IOException.class,
        () -> host.withVerifiedInstalledBundle(APP_ID, (_, _) -> actionRan.getAndSet(true)));

    assertFalse(actionRan.get());
  }

  @Test
  void withVerifiedInstalledBundle_whenInstalledContentTampered_expectActionNeverRuns()
      throws Exception {
    KeyPair signer = signer();
    LocalProcessAppHost host = signedHost(signer);
    InstalledAppSnapshot installed = host.installFromDirectory(signedBundle("1", signer));
    Files.writeString(installed.paths().installedRoot().resolve("content.txt"), "changed");
    AtomicBoolean actionRan = new AtomicBoolean();

    assertThrows(
        IOException.class,
        () -> host.withVerifiedInstalledBundle(APP_ID, (_, _) -> actionRan.getAndSet(true)));

    assertFalse(actionRan.get());
  }

  @Test
  void withVerifiedInstalledBundle_whenSignatureTampered_expectActionNeverRuns() throws Exception {
    KeyPair signer = signer();
    LocalProcessAppHost host = signedHost(signer);
    InstalledAppSnapshot installed = host.installFromDirectory(signedBundle("1", signer));
    Files.writeString(
        installed.paths().installedRoot().resolve("cryptad-app.signature"), "invalid signature");
    AtomicBoolean actionRan = new AtomicBoolean();

    assertThrows(
        IOException.class,
        () -> host.withVerifiedInstalledBundle(APP_ID, (_, _) -> actionRan.getAndSet(true)));

    assertFalse(actionRan.get());
  }

  @Test
  void withVerifiedInstalledBundle_whenPublisherChanges_expectHistoricalTrustRejects()
      throws Exception {
    KeyPair trusted = signer();
    LocalProcessAppHost host = signedHost(trusted);
    InstalledAppSnapshot installed = host.installFromDirectory(signedBundle("1", trusted));
    AppBundleSigner.sign(installed.paths().installedRoot(), KEY_ID, signer().getPrivate());

    assertThrows(IOException.class, () -> host.withVerifiedInstalledBundle(APP_ID, (_, _) -> true));
  }

  @Test
  void rollback_whenDraftCreatedAfterUpdate_expectDataPreservedAndBundleIdentityRestored()
      throws Exception {
    KeyPair signer = signer();
    LocalProcessAppHost host = signedHost(signer);
    InstalledAppSnapshot original = host.installFromDirectory(signedBundle("1", signer));
    String originalIdentity =
        host.withVerifiedInstalledBundle(
            APP_ID, (_, identity) -> identity.signedContentDigestSha256());
    host.updateFromDirectory(APP_ID, signedBundle("2", signer));
    String updatedIdentity =
        host.withVerifiedInstalledBundle(
            APP_ID, (_, identity) -> identity.signedContentDigestSha256());
    Files.createDirectories(original.paths().dataDir());
    Path draft = original.paths().dataDir().resolve("private-draft.txt");
    Files.writeString(draft, "user edit after import");

    host.rollback(APP_ID);

    assertNotEquals(originalIdentity, updatedIdentity);
    assertEquals(
        originalIdentity,
        host.withVerifiedInstalledBundle(
            APP_ID, (_, identity) -> identity.signedContentDigestSha256()));
    assertEquals("user edit after import", Files.readString(draft));
    assertEquals("1", host.describe(APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void withVerifiedInstalledBundle_whenUpdateContends_expectOriginalUntilActionCompletes()
      throws Exception {
    KeyPair signer = signer();
    LocalProcessAppHost host = signedHost(signer);
    host.installFromDirectory(signedBundle("1", signer));
    Path update = signedBundle("2", signer);
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    CompletableFuture<String> guarded = new CompletableFuture<>();
    Thread guard =
        Thread.ofPlatform()
            .unstarted(
                () -> {
                  try {
                    guarded.complete(
                        host.withVerifiedInstalledBundle(
                            APP_ID,
                            (installed, _) -> {
                              entered.countDown();
                              await(release);
                              assertEquals(
                                  "1", host.describe(APP_ID).orElseThrow().manifest().appVersion());
                              return installed.manifest().appVersion();
                            }));
                  } catch (Throwable failure) {
                    guarded.completeExceptionally(failure);
                  }
                });
    CompletableFuture<String> updated = new CompletableFuture<>();
    Thread updater =
        Thread.ofPlatform()
            .unstarted(
                () -> {
                  try {
                    updated.complete(
                        host.updateFromDirectory(APP_ID, update).manifest().appVersion());
                  } catch (Throwable failure) {
                    updated.completeExceptionally(failure);
                  }
                });
    guard.start();
    try {
      assertTrue(entered.await(10, TimeUnit.SECONDS));
      updater.start();
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
      while (updater.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
        Thread.onSpinWait();
      }
      assertEquals(Thread.State.BLOCKED, updater.getState());
      assertFalse(updated.isDone());
    } finally {
      release.countDown();
      guard.join(TimeUnit.SECONDS.toMillis(10));
      updater.join(TimeUnit.SECONDS.toMillis(10));
    }
    assertEquals("1", guarded.get(10, TimeUnit.SECONDS));
    assertEquals("2", updated.get(10, TimeUnit.SECONDS));
  }

  private static void await(CountDownLatch latch) throws IOException {
    try {
      if (!latch.await(20, TimeUnit.SECONDS)) {
        throw new IOException("Test guard timed out.");
      }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new IOException("Test guard interrupted.", interrupted);
    }
  }

  private LocalProcessAppHost signedHost(KeyPair signer) {
    AppBundleVerifier current = AppBundleVerifier.requireSigned(trustedKeys(signer));
    AppBundleVerifier historical =
        AppBundleVerifier.requireSignedForHistoricalVerification(trustedKeys(signer));
    return new LocalProcessAppHost(
        layout(),
        AppInstallVerificationPolicy.requireSignedWithIdentity(
            current::verify, historical::verify));
  }

  private AppHostLayout layout() {
    return new AppHostLayout(
        temporary.resolve("data"), temporary.resolve("cache"), temporary.resolve("run"));
  }

  private static TrustedAppKeys trustedKeys(KeyPair signer) {
    return TrustedAppKeys.of(
        new TrustedAppKey(KEY_ID, AppBundleSignature.SIGNATURE_ALGORITHM, signer.getPublic()));
  }

  private static KeyPair signer() throws Exception {
    return KeyPairGenerator.getInstance(AppBundleSignature.SIGNATURE_ALGORITHM).generateKeyPair();
  }

  private Path signedBundle(String version, KeyPair signer) throws IOException {
    Path staged = bundle(version);
    AppBundleSigner.sign(staged, KEY_ID, signer.getPrivate());
    return staged;
  }

  private Path bundle(String version) throws IOException {
    Path staged = Files.createDirectories(temporary.resolve("stage-" + version));
    Files.createDirectories(staged.resolve("bin"));
    Files.writeString(staged.resolve("bin/launch"), "#!/bin/sh\nexit 0\n");
    Files.writeString(staged.resolve("content.txt"), "bundle " + version);
    Files.writeString(
        staged.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=site-publisher
        app.name=Site Publisher
        app.version=${version}
        app.exec=bin/launch
        app.ui.entry=/
        app.permissions=app.data.read,app.data.write
        quota.data.bytes=1048576
        quota.cache.bytes=1024
        """
            .replace("${version}", version));
    return staged;
  }
}
