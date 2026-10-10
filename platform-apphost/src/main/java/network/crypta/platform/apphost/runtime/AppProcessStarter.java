package network.crypta.platform.apphost.runtime;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Starts AppHost child processes on a dedicated daemon platform thread.
 *
 * <p>The launch thread is independent of the caller's request thread. This matters for Linux
 * sandbox launchers using {@code --die-with-parent}: a request worker can end while the AppHost JVM
 * and its child remain active. This helper starts processes but leaves their tracking and
 * termination to the caller.
 */
final class AppProcessStarter {
  /** Prevents instantiation of this process-launch utility. */
  private AppProcessStarter() {}

  /**
   * Starts the supplied process plan and waits for its process handle or launch failure.
   *
   * <p>Launches are serialized on one daemon platform thread. If the caller is interrupted while
   * waiting, this method continues until the launch outcome is known, then restores the caller's
   * interrupt flag. A successful return transfers responsibility for the process to the caller;
   * this helper does not supervise or stop it.
   *
   * @param builder the fully prepared command, environment, and redirects; the caller must not
   *     modify it until this method returns
   * @return the started process for the caller to track and clean up
   * @throws IOException if process creation fails or the launch reports an unexpected checked
   *     failure
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

  /** Initializes the launch executor only when the first process is started. */
  private static final class Launcher {
    /** Prevents instantiation of the executor holder. */
    private Launcher() {}

    /** Keeps launch work off virtual threads and short-lived request workers. */
    private static final java.util.concurrent.ExecutorService EXECUTOR =
        Executors.newSingleThreadExecutor(
            Thread.ofPlatform().daemon().name("cryptad-app-process-launcher").factory());
  }
}
