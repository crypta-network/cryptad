package network.crypta.platform.apphost.runtime;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import network.crypta.fs.AppEnv;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalProcessRequestOwnersTest {
  @Test
  void stopInterruptsOnlyItsLiveLaunchRequestAndNeverAClosedRegistration(@TempDir Path root)
      throws Exception {
    var host = host(root);
    host.installFromDirectory(stage(root, "owner-a"));
    host.installFromDirectory(stage(root, "owner-b"));
    host.start("owner-a");
    host.start("owner-b");
    var a = host.currentLaunch("owner-a").orElseThrow();
    var b = host.currentLaunch("owner-b").orElseThrow();
    var entered = new CountDownLatch(3);
    var release = new CountDownLatch(1);
    var first = owner(host, "owner-a", a.launchId(), false, entered, release);
    var other = owner(host, "owner-b", b.launchId(), false, entered, release);
    var closed = owner(host, "owner-a", a.launchId(), true, entered, release);
    try {
      assertTrue(entered.await(10, TimeUnit.SECONDS));
      assertTrue(host.stop("owner-a"));
      assertTrue(first.get(10, TimeUnit.SECONDS));
      assertFalse(other.isDone());
      assertFalse(closed.isDone());
      release.countDown();
      assertFalse(other.get(10, TimeUnit.SECONDS));
      assertFalse(closed.get(10, TimeUnit.SECONDS));
    } finally {
      release.countDown();
      host.stop("owner-a");
      host.stop("owner-b");
    }
  }

  @Test
  void supersededLaunchIsRejectedAndClosedCapacityCanBeReused(@TempDir Path root) throws Exception {
    var host = host(root);
    host.installFromDirectory(stage(root, "owner-a"));
    host.start("owner-a");
    String old = host.currentLaunch("owner-a").orElseThrow().launchId();
    host.stop("owner-a");
    assertTrue(host.registerRequestOwner("owner-a", old).isEmpty());
    host.start("owner-a");
    String current = host.currentLaunch("owner-a").orElseThrow().launchId();
    var leases = new ArrayList<AppHost.RequestOwner>();
    try {
      assertFalse(old.equals(current));
      assertTrue(host.registerRequestOwner("owner-a", old).isEmpty());
      for (int index = 0; index < 256; index++) {
        leases.add(host.registerRequestOwner("owner-a", current).orElseThrow());
      }
      assertThrows(AppHostException.class, () -> host.registerRequestOwner("owner-a", current));
      leases.removeLast().close();
      leases.add(host.registerRequestOwner("owner-a", current).orElseThrow());
      assertEquals(256, leases.size());
    } finally {
      for (var lease : leases) lease.close();
      host.stop("owner-a");
    }
    assertFalse(Thread.currentThread().isInterrupted());
  }

  private static CompletableFuture<Boolean> owner(
      LocalProcessAppHost host,
      String app,
      String launch,
      boolean closeEarly,
      CountDownLatch entered,
      CountDownLatch release) {
    var result = new CompletableFuture<Boolean>();
    Thread.ofVirtual()
        .start(
            () -> {
              try (var owner = host.registerRequestOwner(app, launch).orElseThrow()) {
                if (closeEarly) owner.close();
                entered.countDown();
                try {
                  if (!release.await(10, TimeUnit.SECONDS))
                    throw new AssertionError("request owner timeout");
                  result.complete(owner.cancellationRequested());
                } catch (InterruptedException _) {
                  Thread.currentThread().interrupt();
                  result.complete(owner.cancellationRequested());
                }
              } catch (Throwable failure) {
                result.completeExceptionally(failure);
              }
            });
    return result;
  }

  private static LocalProcessAppHost host(Path root) {
    Assumptions.assumeFalse(new AppEnv().isWindows());
    return new LocalProcessAppHost(
        new AppHostLayout(root.resolve("data"), root.resolve("cache"), root.resolve("run")),
        Duration.ofSeconds(2),
        new java.security.SecureRandom(),
        AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnly());
  }

  private static Path stage(Path root, String app) throws Exception {
    Path staged = Files.createDirectories(root.resolve("stage-" + app));
    Path script = staged.resolve("run.sh");
    Files.writeString(script, "#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n");
    Files.setPosixFilePermissions(script, PosixFilePermissions.fromString("rwx------"));
    Files.writeString(
        staged.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=Request owner fixture
        app.version=1.0.0
        app.exec=run.sh
        app.permissions=content.fetch
        """
            .formatted(app));
    return staged;
  }
}
