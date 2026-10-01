package network.crypta.platform.apphost.runtime;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Creates application processes from a platform thread that lives as long as the JVM. */
final class AppProcessStarter {
  private AppProcessStarter() {}

  /**
   * Starts the supplied private process plan without tying the child's lifetime to a request
   * thread.
   *
   * <p>On Linux, bubblewrap's parent-death signal follows the thread that creates the process. HTTP
   * pool workers can expire while the host JVM remains alive. The daemon platform worker therefore
   * remains available for the JVM lifetime. Caller interruption is restored after the launch result
   * is retrieved so that a launched child cannot be abandoned without returning its process handle.
   *
   * @param builder the fully prepared command, environment and redirects owned by the caller
   * @return the started process, still subject to normal AppHost tracking and cleanup
   * @throws IOException if process creation fails
   */
  static Process start(ProcessBuilder builder) throws IOException {
    Future<Process> launch = Launcher.EXECUTOR.submit(builder::start);
    boolean interrupted = false;
    try {
      while (true) {
        try {
          return launch.get();
        } catch (InterruptedException _) {
          interrupted = true;
        } catch (ExecutionException failure) {
          Throwable cause = failure.getCause();
          if (cause instanceof IOException exception) throw exception;
          if (cause instanceof RuntimeException exception) throw exception;
          if (cause instanceof Error error) throw error;
          throw new IOException("App process creation failed", cause);
        }
      }
    } finally {
      if (interrupted) Thread.currentThread().interrupt();
    }
  }

  private static final class Launcher {
    private Launcher() {}

    // A virtual thread or expiring worker would reproduce the parent-death defect.
    private static final java.util.concurrent.ExecutorService EXECUTOR =
        Executors.newSingleThreadExecutor(
            Thread.ofPlatform().daemon().name("cryptad-app-process-launcher").factory());
  }
}
