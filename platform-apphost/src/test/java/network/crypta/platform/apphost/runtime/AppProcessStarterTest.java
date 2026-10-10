package network.crypta.platform.apphost.runtime;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class AppProcessStarterTest {
  @Test
  void start_whenCallerIsInterrupted_returnsProcessAndPreservesInterruption() throws Exception {
    AppEnv environment = new AppEnv();
    Path java =
        Path.of(
            System.getProperty("java.home"), "bin", environment.isWindows() ? "java.exe" : "java");
    Process process = null;
    Thread.currentThread().interrupt();
    try {
      process =
          AppProcessStarter.start(
              new ProcessBuilder(java.toString(), "-version").redirectErrorStream(true));

      assertTrue(Thread.currentThread().isInterrupted());
      assertTrue(process.pid() > 0);
    } finally {
      assertTrue(Thread.interrupted());
      if (process != null) {
        if (!process.waitFor(5, TimeUnit.SECONDS)) process.destroyForcibly();
        assertTrue(process.waitFor(5, TimeUnit.SECONDS));
      }
    }
  }

  @Test
  void start_whenCommandDoesNotExist_propagatesLaunchFailure() {
    ProcessBuilder builder = new ProcessBuilder("cryptad-nonexistent-process-starter-test");

    assertThrows(IOException.class, () -> AppProcessStarter.start(builder));
  }

  @Test
  void start_whenCallerThreadExits_keepsParentProtectedSandboxAlive() throws Exception {
    assumeTrue(new AppEnv().isLinux() && Files.isExecutable(Path.of("/usr/bin/bwrap")));
    CompletableFuture<Process> started = new CompletableFuture<>();
    CountDownLatch releaseCaller = new CountDownLatch(1);
    Thread caller =
        Thread.ofPlatform()
            .start(
                () -> {
                  try {
                    Process process =
                        AppProcessStarter.start(
                            new ProcessBuilder(
                                    "/usr/bin/bwrap",
                                    "--die-with-parent",
                                    "--ro-bind",
                                    "/",
                                    "/",
                                    "--",
                                    "/bin/sh",
                                    "-c",
                                    "echo READY; exec /bin/sleep 25")
                                .redirectErrorStream(true));
                    started.complete(process);
                    releaseCaller.await();
                  } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    started.completeExceptionally(failure);
                  } catch (Exception failure) {
                    started.completeExceptionally(failure);
                  }
                });
    Process process = null;
    try {
      process = started.get(10, TimeUnit.SECONDS);
      try (BufferedReader output =
          new BufferedReader(
              new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
        assertEquals("READY", output.readLine());
        assertTrue(process.isAlive());

        releaseCaller.countDown();
        caller.join(3000);

        assertFalse(caller.isAlive());
        assertFalse(process.waitFor(2, TimeUnit.SECONDS));
        assertTrue(process.isAlive());
      }
    } finally {
      releaseCaller.countDown();
      caller.join(3000);
      if (process != null) {
        process.destroyForcibly();
        assertTrue(process.waitFor(5, TimeUnit.SECONDS));
      }
    }
  }
}
