package network.crypta.clients.fcp;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Random;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;

/**
 * Coordinates Direct Disk Access (DDA) authorization for client requests handled by the FCP server.
 *
 * <p>This controller tracks directories that have already passed a DDA read and/or write test,
 * caches the resulting {@link DirectoryAccess} verdicts, and answers future access checks without
 * performing redundant filesystem probes. It also queues {@link DdaCheckJob} instances that craft
 * deterministic marker files so external clients can deliberately prove that the node can touch the
 * desired directory tree.
 *
 * <p>Callers typically obtain a single instance from {@link FCPServer}, invoke {@link
 * #enqueueDDACheck(String, boolean, boolean)} to create a job, feed the result back through {@link
 * #registerTestDDAResult(String, boolean, boolean)}, and later query {@link #allowDDAFrom(File,
 * boolean)} whenever an upload or download request references new filesystem paths. All access to
 * the mutable state is synchronized on internal maps, making the controller thread-safe provided
 * callers honor the provided APIs and avoid bypassing the caches through reflection or mutation of
 * shared fields.
 *
 * <p><strong>Responsibilities</strong>
 *
 * <ul>
 *   <li>Cache per-directory read/write verdicts once a DDA test completes successfully.
 *   <li>Queue and manage {@link DdaCheckJob} instances so only one test runs per directory.
 *   <li>Delete temporary artifacts left behind by test jobs when shutting down or cleaning up.
 * </ul>
 *
 * @see DdaCheckJob
 */
final class DdaAccessController {
  private final FCPServer server;
  private final Logger log;
  private final HashMap<String, DirectoryAccess> checkedDirectories = new HashMap<>();
  private final HashMap<File, DdaCheckJob> inTestDirectories = new HashMap<>();

  /**
   * Creates a controller bound to the supplied server and logger pair.
   *
   * <p>The caller is expected to pass the canonical {@link FCPServer} instance so decisions about
   * default permission modes reflect the node's configuration. The {@link Logger} is retained for
   * detailed trace logging when DDA tests succeed or fail. Neither dependency is optional; callers
   * should construct the controller during server startup and keep it alive for the server's
   * lifetime to avoid losing cached directory verdicts.
   *
   * @param server provides node state, fast random sources, and DDA defaults for fallback checks.
   * @param log records debug, warning, and error information related to individual test runs.
   */
  DdaAccessController(FCPServer server, Logger log) {
    this.server = server;
    this.log = log;
  }

  /**
   * Determines whether the node may perform a DDA read or write in the directory of the provided
   * file reference.
   *
   * <p>The method resolves the canonical parent directory, looks up prior {@link DirectoryAccess}
   * verdicts, and falls back to {@link FCPServer#isUploadDDAAlwaysAllowed()} or {@link
   * FCPServer#isDownloadDDAAlwaysAllowed()} when no explicit test result exists. The decision is
   * entirely cache-based; callers must ensure they previously registered fresh permissions whenever
   * the filesystem state or policy changes. The method is thread-safe and may be invoked frequently
   * in the hot path of request dispatching.
   *
   * <pre>{@code
   * if (controller.allowDDAFrom(new File("/tmp/data"), true)) {
   *   server.startDownload();
   * }
   * }</pre>
   *
   * @param filename representative file whose parent directory should be evaluated for access.
   * @param writeRequest {@code true} when checking downloads/writes, {@code false} for read
   *     uploads.
   * @return {@code true} when cached permissions or server defaults authorize the requested mode.
   */
  boolean allowDDAFrom(File filename, boolean writeRequest) {
    String parentDirectory = FileUtil.getCanonicalFile(filename).getParent();
    DirectoryAccess access;
    synchronized (checkedDirectories) {
      access = checkedDirectories.get(parentDirectory);
    }
    if (log.isDebugEnabled()) {
      log.debug("Checking DDA: {} for {}", access, parentDirectory);
    }
    if (writeRequest) {
      return access == null ? server.isDownloadDDAAlwaysAllowed() : access.canWrite;
    } else {
      return access == null ? server.isUploadDDAAlwaysAllowed() : access.canRead;
    }
  }

  /**
   * Stores the result of a previously executed DDA test for the supplied directory path.
   *
   * <p>Callers should invoke this method immediately after a {@link DdaCheckJob} reports whether it
   * could read or write inside the directory. The controller replaces any prior verdict for the
   * same canonical path so stale authorizations do not linger. The cache is synchronized to ensure
   * that concurrent test completions for distinct directories remain consistent without additional
   * locking by the caller.
   *
   * @param path canonical directory string whose cached access rights should be updated atomically.
   * @param read {@code true} when the test proved read access is possible without privilege
   *     escalation.
   * @param write {@code true} when the test proved a temporary file can be written and cleaned up.
   */
  void registerTestDDAResult(String path, boolean read, boolean write) {
    DirectoryAccess access = new DirectoryAccess(read, write);
    synchronized (checkedDirectories) {
      checkedDirectories.put(path, access);
    }
    if (log.isDebugEnabled()) {
      log.debug("DDA: read={} write={} for {}", read, write, path);
    }
  }

  /**
   * Queues a new {@link DdaCheckJob} for the provided directory and desired access types.
   *
   * <p>The controller validates that the directory exists, rejects duplicate concurrent checks, and
   * constructs temporary marker files tailored to the requested read or write assertions. When read
   * testing is enabled the method creates, populates, and schedules deletion of a random file so
   * the job can later verify its contents. When write testing is enabled the job records a random
   * filename for remote clients to manipulate. The returned job is ready for serialization through
   * FCP responses.
   *
   * @param path filesystem directory path supplied by the client and already sanitized by callers.
   * @param read {@code true} to include read verification, {@code false} to skip creating test
   *     data.
   * @param write {@code true} to request write verification, including unique temporary filenames.
   * @return configured job containing marker filenames and expected file contents for validation.
   * @throws IllegalArgumentException if the path is invalid or already under active testing.
   */
  DdaCheckJob enqueueDDACheck(String path, boolean read, boolean write) {
    File directory = FileUtil.getCanonicalFile(new File(path));
    if (!directory.exists() || !directory.isDirectory()) {
      throw new IllegalArgumentException(
          "The specified path isn't a directory! or doesn't exist or the node doesn't have access"
              + " to it!");
    }

    DdaCheckJob existing;
    synchronized (inTestDirectories) {
      existing = inTestDirectories.get(directory);
    }
    if (existing != null) {
      throw new IllegalArgumentException("There is already a TestDDA going on for that directory!");
    }

    Random fastWeakRandom = server.runtime().randomness().fastWeakRandom();
    File writeFile = write ? new File(path, "DDACheck-" + fastWeakRandom.nextInt() + ".tmp") : null;
    File readFile = null;
    if (read) {
      try {
        readFile = File.createTempFile("DDACheck-", ".tmp", directory);
        readFile.deleteOnExit();
      } catch (IOException e) {
        log.warn("Unable to create read test file in {}", directory, e);
      }
    }

    DdaCheckJob job = new DdaCheckJob(fastWeakRandom, directory, readFile, writeFile);

    if (readFile != null) {
      try (FileOutputStream fos = new FileOutputStream(readFile);
          BufferedOutputStream bos = new BufferedOutputStream(fos)) {
        bos.write(job.readContent.getBytes(StandardCharsets.UTF_8));
      } catch (IOException e) {
        log.error("Got a IOE while creating the file ({} ! {}", readFile, e.getMessage());
      }
    }

    synchronized (inTestDirectories) {
      inTestDirectories.put(directory, job);
    }
    return job;
  }

  /**
   * Removes and returns the active {@link DdaCheckJob} associated with the provided directory.
   *
   * <p>This call mirrors {@link #enqueueDDACheck(String, boolean, boolean)} and should be used
   * after the job completes or times out so the controller can accept future checks targeting the
   * same directory. The method performs the same canonical-path validation and throws the standard
   * exception if the directory is missing to prevent accidental clean-up of unrelated locations.
   *
   * @param path canonical directory path previously supplied while enqueuing a DDA verification.
   * @return the job that was tracking verification state, or {@code null} when none was stored.
   * @throws IllegalArgumentException if the directory no longer exists or is not a directory.
   */
  DdaCheckJob popDDACheck(String path) {
    File directory = FileUtil.getCanonicalFile(new File(path));
    if (!directory.exists() || !directory.isDirectory()) {
      throw new IllegalArgumentException(
          "The specified path isn't a directory! or doesn't exist or the node doesn't have access"
              + " to it!");
    }
    synchronized (inTestDirectories) {
      return inTestDirectories.remove(directory);
    }
  }

  /**
   * Discards all queued DDA jobs and deletes any temporary files created for read tests.
   *
   * <p>Call this method during shutdown or after fatal errors to guarantee that orphaned temporary
   * files do not accumulate on disk. The method iterates through the tracked jobs, attempts to
   * delete any read marker files, and logs non-fatal failures while keeping the rest of the
   * clean-up proceeding. Because the underlying map is synchronized, the cleanup safely coexists
   * with other job lifecycle operations.
   */
  void freeDDAJobs() {
    synchronized (inTestDirectories) {
      for (DdaCheckJob job : inTestDirectories.values()) {
        if (job.readFilename != null) {
          try {
            Files.deleteIfExists(job.readFilename.toPath());
          } catch (IOException e) {
            log.warn("Unable to delete DDA test file {}", job.readFilename, e);
          }
        }
      }
    }
  }

  private record DirectoryAccess(boolean canRead, boolean canWrite) {}
}
