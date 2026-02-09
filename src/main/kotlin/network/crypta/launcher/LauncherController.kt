package network.crypta.launcher

import java.awt.Desktop
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.BasicFileAttributes
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*
import network.crypta.fs.AppEnv

// Log buffering strategy
// - Keep a small replay window so late subscribers get recent lines
// - Cap extra capacity and drop the oldest entries under backpressure to stay memory-bounded
private const val LOG_REPLAY: Int = 200
private const val LOG_EXTRA_CAPACITY: Int = 300
private const val TAIL_BASE_DELAY_MS: Long = 200
private const val TAIL_MAX_DELAY_MS: Long = 1500
private const val TAIL_CANCEL_POLL_MS: Long = 50
private const val TAIL_READ_CHUNK: Int = 64 * 1024

/**
 * Coordinates the launcher lifecycle for the Crypta daemon process and exposes the UI-facing state.
 *
 * This controller resolves the wrapper script, starts the process, streams combined stdout/stderr,
 * tails `wrapper.log` when available, and updates an in-memory [AppState] snapshot for the UI. It
 * also extracts the FProxy port from log output to enable browser launch. Long-running work is
 * dispatched onto the provided I/O dispatcher, while state updates are funneled through the
 * supplied coroutine scope. The lifecycle is intentionally idempotent: repeated start/stop calls
 * either return quickly or re-enter the same terminal states without throwing.
 * <ul>
 * <li>Start and stop the wrapper process with platform-specific behavior.</li>
 * <li>Expose logs via a bounded shared flow for UI consumption.</li>
 * <li>Track running state, shutdown intent, and detected HTTP port.</li>
 * </ul>
 *
 * @param scope parent scope for launcher coroutines and UI-bound updates.
 * @param io dispatcher used for process I/O and filesystem operations.
 * @param cwd working directory used to resolve and launch the wrapper script.
 */
class LauncherController(
  private val scope: CoroutineScope,
  private val io: CoroutineDispatcher = Dispatchers.IO,
  private val cwd: Path = Paths.get(System.getProperty("user.dir")),
) {
  private val _state = MutableStateFlow(AppState())

  /**
   * Read-only stream of the latest [AppState] snapshot for UI rendering. The flow is eagerly
   * started and always available, reflecting changes made by [start], [stop], and shutdown calls.
   * Consumers should treat the state as immutable and use it as a point-in-time view only.
   */
  val state: StateFlow<AppState> = _state.stateIn(scope, SharingStarted.Eagerly, _state.value)

  /**
   * Bounded, drop-older log stream.
   *
   * We keep a small replay window so late subscribers still see the latest lines. We also cap total
   * in-memory buffering to avoid memory pressure when the daemon is chatty or the UI is momentarily
   * stalled.
   *
   * Total buffer = [LOG_REPLAY] + [LOG_EXTRA_CAPACITY]. When full, the oldest entries are dropped.
   */
  private val _logs =
    MutableSharedFlow<String>(
      replay = LOG_REPLAY,
      extraBufferCapacity = LOG_EXTRA_CAPACITY,
      onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

  /**
   * Bounded, drop-older log stream for launcher and daemon output. A small replay window is kept so
   * late subscribers still receive recent lines; when buffers fill, older entries are dropped to
   * stay memory-bounded. Emissions are best-effort and do not suspend the caller.
   */
  val logs: SharedFlow<String> = _logs.asSharedFlow()

  private var process: Process? = null
  private var tailJob: Job? = null
  private var autoOpenedBrowser = false
  private var wrapperConfPath: Path? = null

  // Separate shutdown scope so quit can proceed even if the UI scope is canceled
  private val shutdownScope: CoroutineScope = CoroutineScope(SupervisorJob() + io)

  /**
   * Launch the wrapper process if it is not already running.
   *
   * This method resolves the wrapper script from [cwd], validates that it is executable, and logs a
   * readable command line for diagnostics. It starts the process with merged stdout/stderr and
   * spins up coroutines to read output, detect the FProxy port, watch for exit, and optionally tail
   * `wrapper.log`. The call returns immediately; all work happens asynchronously on [io]. Repeated
   * calls while running are ignored.
   */
  fun start() {
    if (_state.value.isRunning || process?.isAlive == true) return
    scope.launch(io) {
      val cryptadPath = resolveCryptadPath(cwd)
      if (!Files.isRegularFile(cryptadPath) || !Files.isExecutable(cryptadPath)) {
        logLine(ts() + " ERROR: Cannot find executable 'cryptad' at $cryptadPath")
        return@launch
      }

      logLine(ts() + " Starting '" + cryptadPath.fileName + "' ...")
      updateState { it.copy(isRunning = true, knownPort = null) }

      // Ensure wrapper.conf flush optimization if available
      tryEnableConsoleFlush(cryptadPath)

      val cmd = buildCryptadCommand(cryptadPath)
      // Log the effective command and working directory for diagnostics
      logLine(
        ts() +
          " exec: " +
          formatCommandForLog(cmd) +
          " (cwd=" +
          cwd.toAbsolutePath().toString() +
          ")"
      )
      val pb = ProcessBuilder(cmd)
      pb.redirectErrorStream(true)
      pb.directory(cwd.toFile())
      val p = pb.start()
      process = p

      // Reader: combined stdout+stderr
      scope.launch { readProcessOutput(p) }
      // Watcher: termination
      scope.launch { watchProcess(p) }
      // Tail wrapper.log if present
      tailJob?.cancel()
      guessWrapperConfPathForCryptadScript(cryptadPath)?.let { conf ->
        wrapperConfPath = conf
        val logSpec = readWrapperProperty(conf, "wrapper.logfile")
        val logPath = computeWrapperLogPath(conf, logSpec)
        tailJob =
          scope.launch(Dispatchers.IO) {
            val thisJob = coroutineContext[Job] ?: return@launch
            tailFileWhileAlive(logPath, thisJob)
          }
      }
    }
  }

  /**
   * Request a graceful stop of the wrapper process if it is running.
   *
   * The controller updates the state to indicate a stop is in progress and then attempts the
   * platform appropriate shutdown (anchor-file signaling on Windows, signal escalation on Unix).
   * The call returns immediately; waiting happens on [io] and is best-effort. If the process is
   * already stopped, the state is normalized and the method exits without further work.
   */
  fun stop() {
    val p = process ?: return
    if (!p.isAlive) {
      updateState { it.copy(isRunning = false) }
      return
    }
    scope.launch(io) {
      updateState { it.copy(isStopping = true) }
      try {
        stopProcessGracefully(p)
      } finally {
        updateState { it.copy(isStopping = false) }
      }
    }
  }

  /**
   * Open the local FProxy URL in the default browser when a port is known.
   *
   * This method uses the desktop integration when available and falls back to platform-specific
   * commands (`open`, `rundll32`, or `xdg-open`). If no port has been detected yet, it is a no-op.
   * Errors are logged but do not propagate to the caller.
   */
  fun launchBrowser() {
    val port = _state.value.knownPort ?: return
    val uri = URI.create("http://localhost:$port/")
    scope.launch(io) {
      try {
        if (Desktop.isDesktopSupported()) {
          val d = Desktop.getDesktop()
          if (d.isSupported(Desktop.Action.BROWSE)) {
            d.browse(uri)
            return@launch
          }
        }
        val env = AppEnv()
        if (env.isMac()) {
          ProcessBuilder("open", uri.toString()).start()
        } else if (env.isWindows()) {
          ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", uri.toString()).start()
        } else {
          ProcessBuilder("xdg-open", uri.toString()).start()
        }
      } catch (t: Throwable) {
        logLine(ts() + " ERROR: Failed to launch browser: ${t.message}")
      }
    }
  }

  /**
   * Begin to shut down and return immediately.
   *
   * This method marks the controller as shutting down and initiates a stop on a dedicated shutdown
   * scope, so the request is honored even if the UI scope has been canceled. It is safe to call
   * multiple times; further calls are ignored once shutdown has started.
   */
  fun shutdown() {
    if (_state.value.isShuttingDown) return
    updateState { it.copy(isShuttingDown = true) }
    shutdownScope.launch { process?.let { p -> if (p.isAlive) stopProcessGracefully(p) } }
  }

  /**
   * Suspend until the wrapper process has fully exited after shutdown is requested.
   *
   * If shutdown is already in progress, this method waits for the current process to terminate and
   * returns. Otherwise, it marks shutdown, issues a graceful stop, and suspends on [io] until the
   * process tree has exited or escalation completes. The method is idempotent and safe to call from
   * repeated lifecycle paths such as window close handlers or test teardown hooks.
   */
  suspend fun shutdownAndWait() {
    if (_state.value.isShuttingDown) {
      // If already shutting down, just wait until not running
      val p = process
      if (p != null && p.isAlive) stopProcessGracefully(p)
      return
    }
    updateState { it.copy(isShuttingDown = true) }
    withContext(io) { process?.let { p -> if (p.isAlive) stopProcessGracefully(p) } }
  }

  // --- internals ---

  private suspend fun readProcessOutput(p: Process) {
    withContext(io) {
      BufferedReader(InputStreamReader(p.inputStream, StandardCharsets.UTF_8)).use { br ->
        var line: String?
        while (br.readLine().also { line = it } != null) {
          val s = line!!
          logLine(s)
          parseFProxyPortFromLine(s)?.let { port ->
            val old = _state.value.knownPort
            if (old != port) updateState { it.copy(knownPort = port) }
            if (!autoOpenedBrowser) {
              autoOpenedBrowser = true
              launchBrowser()
            }
          }
        }
      }
    }
  }

  private suspend fun watchProcess(p: Process) {
    withContext(io) {
      val exit =
        try {
          p.waitFor()
        } catch (_: InterruptedException) {
          return@withContext
        }
      logLine(ts() + " cryptad exited with code $exit")
      process = null
      updateState { it.copy(isRunning = false) }
    }
  }

  /**
   * Tail the given file while the wrapper process stays alive, emitting appended lines to the UI
   * log stream. Uses a single `RandomAccessFile` instance to reduce open/close churn and reopens on
   * rotation/truncation. All resource operations are guarded and closed in `finally` to avoid leaks
   * on exceptions or coroutine cancellation.
   */
  private fun tailFileWhileAlive(path: Path, tailingJob: Job) {
    // Keep a single RAF open to avoid repeated open/close churn. Add exponential backoff when no
    // new data arrives to reduce filesystem pressure. Re-open on file rotation or truncation.
    val state = TailState()
    try {
      while (tailingJob.isActive && (process?.isAlive == true)) {
        try {
          val madeProgress = tailOnce(path, state)
          state.idleCount = if (madeProgress) 0 else state.idleCount + 1
        } catch (_: Throwable) {
          resetTailOnError(state)
        }
        if (!sleepWhileJobActive(tailingJob, calcTailDelayMs(state.idleCount))) {
          return
        }
      }
    } finally {
      closeTailFile(state)
    }
  }

  private fun sleepWhileJobActive(job: Job, delayMs: Long): Boolean {
    var remaining = delayMs
    while (remaining > 0) {
      if (!job.isActive) return false
      val chunk = minOf(remaining, TAIL_CANCEL_POLL_MS)
      try {
        Thread.sleep(chunk)
      } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        return false
      }
      remaining -= chunk
    }
    return job.isActive
  }

  private suspend fun stopProcessGracefully(p: Process) {
    try {
      val pid = p.pid()
      val isWindows = AppEnv().isWindows()
      // Snapshot descendants before we start signaling to avoid losing them if the root dies early
      val snapshot = getDescendantTreePids(pid)
      val allPids = listOf(pid) + snapshot

      if (isWindows) {
        // Prefer a graceful stop via a Wrapper anchor file on Windows. Falls back to task-kill.
        if (!tryWindowsGracefulStopViaAnchor(allPids)) {
          runCmd("cmd", "/c", "taskkill /PID $pid /T")
          if (!waitForPidsToExit(allPids, 20_000)) {
            runCmd("cmd", "/c", "taskkill /F /PID $pid /T")
            waitForPidsToExit(allPids, 5_000)
          }
        }
      } else {
        logLine(ts() + " Sending SIGINT to wrapper tree (root PID $pid) ...")
        killUnixSignalPids(allPids, "INT")
        if (!waitForPidsToExit(allPids, 20_000)) {
          logLine(ts() + " Escalating: sending SIGTERM to remaining processes ...")
          killUnixSignalPids(allPids.filter { isPidAlive(it) }, "TERM")
          if (!waitForPidsToExit(allPids, 5_000)) {
            logLine(ts() + " Escalating: sending SIGKILL to remaining processes ...")
            killUnixSignalPids(allPids.filter { isPidAlive(it) }, "KILL")
            waitForPidsToExit(allPids, 2_000)
          }
        }
      }

      if (p.isAlive) p.destroyForcibly()
    } catch (t: Throwable) {
      logLine(ts() + " ERROR: Failed to stop process: ${t.message}")
    }
  }

  private fun getDescendantTreePids(rootPid: Long): List<Long> =
    try {
      val opt = ProcessHandle.of(rootPid)
      if (!opt.isPresent) {
        emptyList()
      } else {
        val root = opt.get()
        root
          .descendants()
          .map(java.util.function.Function<ProcessHandle, Long> { it.pid() })
          .toList()
      }
    } catch (_: Throwable) {
      emptyList()
    }

  private fun isPidAlive(pid: Long): Boolean =
    try {
      ProcessHandle.of(pid).map { it.isAlive }.orElse(false)
    } catch (_: Throwable) {
      false
    }

  /**
   * Suspend until all `pids` have exited or until `millis` has elapsed. Uses coroutines (`delay`)
   * instead of blocking the thread.
   */
  private suspend fun waitForPidsToExit(pids: List<Long>, millis: Long): Boolean {
    val deadline = System.nanoTime() + millis * 1_000_000
    while (System.nanoTime() < deadline) {
      if (pids.none { isPidAlive(it) }) return true
      delay(200)
    }
    return pids.none { isPidAlive(it) }
  }

  private fun killUnixSignalPids(pids: List<Long>, signal: String) {
    pids.forEach { pid ->
      try {
        runCmd("sh", "-lc", "kill -$signal $pid")
      } catch (t: Throwable) {
        // Best-effort signal delivery; log at debug level only to avoid noise when pids exit early
        logDebug("Failed to send SIG$signal to PID $pid", t)
      }
    }
  }

  private fun runCmd(vararg args: String): Boolean =
    try {
      val pr = ProcessBuilder(*args).start()
      pr.waitFor() == 0
    } catch (t: Throwable) {
      logDebug("Command failed: ${args.joinToString(" ")}", t)
      false
    }

  /**
   * Windows-only: Request a graceful shutdown by removing the Tanuki Wrapper anchor file declared
   * in `wrapper.conf` (`wrapper.anchorfile`). Attempts the deletion without a prior existence check
   * to avoid TOCTOU race conditions.
   *
   * @return true only if the anchor file was successfully deleted and all tracked processes exited
   *   within the grace period; returns false immediately if the anchor did not exist or deletion
   *   failed.
   */
  private suspend fun tryWindowsGracefulStopViaAnchor(allPids: List<Long>): Boolean {
    // Prefer anchorfile from wrapper.conf, but fall back to our batch default:
    //   "%LOCALAPPDATA%\Cryptad.anchor".
    val conf = wrapperConfPath
    val anchorSpec = if (conf != null) readWrapperProperty(conf, "wrapper.anchorfile") else null
    val workingDir = if (conf != null) readWrapperProperty(conf, "wrapper.working.dir") else null
    val anchorPath: Path =
      runCatching {
          var p: Path? =
            if (conf != null) computeWrapperFilePath(conf, anchorSpec, workingDir) else null
          if (p == null) {
            val lad = System.getenv("LOCALAPPDATA")
            require(!lad.isNullOrBlank()) { "LOCALAPPDATA not set" }
            p = Paths.get(lad).resolve("Cryptad.anchor").normalize()
          }
          requireNotNull(p)
        }
        .getOrElse {
          return false
        }

    val deleted: Boolean =
      runCatching { Files.deleteIfExists(anchorPath) }
        .onFailure {
          logLine(ts() + " WARN: Failed to delete anchor file at $anchorPath: ${it.message}")
        }
        .getOrDefault(false)
    return if (deleted) {
      logLine(ts() + " Requested graceful shutdown via anchor: ${anchorPath.fileName} ...")
      // Give the wrapper time to observe deletion and stop the JVM
      waitForPidsToExit(allPids, 25_000)
    } else {
      logLine(
        ts() +
          " Anchor file not found or not deleted at $anchorPath; skipping wait for anchor stop."
      )
      false
    }
  }

  private fun tryEnableConsoleFlush(cryptadPath: Path) {
    try {
      val conf = guessWrapperConfPathForCryptadScript(cryptadPath) ?: return
      if (!Files.isRegularFile(conf)) return
      val lines = Files.readAllLines(conf, StandardCharsets.UTF_8).toList()
      val props = parseWrapperProperties(lines)
      if (props["wrapper.console.flush"]?.equals("TRUE", ignoreCase = true) == true) return
      val updated = upsertWrapperProperty(lines, "wrapper.console.flush", "TRUE")
      Files.write(conf, updated, StandardCharsets.UTF_8)
    } catch (_: Throwable) {
      // best-effort only
    }
  }

  /** Read a single property from `wrapper.conf`. Returns null on any error or when absent. */
  private fun readWrapperProperty(conf: Path, key: String): String? =
    runCatching {
        Files.newBufferedReader(conf, StandardCharsets.UTF_8).useLines { lines ->
          lines.firstNotNullOfOrNull { extractWrapperProperty(it, key) }
        }
      }
      .getOrNull()

  private fun extractWrapperProperty(raw: String, key: String): String? {
    val line = raw.trim()
    if (line.isEmpty() || line.startsWith("#")) return null
    val idx = line.indexOf('=')
    if (idx <= 0) return null
    val k = line.substring(0, idx).trim()
    if (k != key) return null
    return line.substring(idx + 1).trim()
  }

  private class TailState {
    var raf: RandomAccessFile? = null
    var currentKey: Any? = null
    var pos: Long = 0
    var leftover: StringBuilder = StringBuilder()
    var idleCount: Int = 0
  }

  private fun calcTailDelayMs(idleCount: Int): Long {
    val shifts = idleCount.coerceAtMost(3) // 200, 400, 800, 1600ms
    val d = TAIL_BASE_DELAY_MS shl shifts
    return d.coerceAtMost(TAIL_MAX_DELAY_MS)
  }

  private fun resetTailOnError(state: TailState) {
    closeTailFile(state)
    state.currentKey = null
    state.idleCount++
  }

  private fun closeTailFile(state: TailState) {
    val toClose = state.raf
    state.raf = null
    try {
      toClose?.close()
    } catch (_: Throwable) {
      // best-effort close; ignore
    }
  }

  private fun tailOnce(path: Path, state: TailState): Boolean {
    if (!Files.exists(path)) {
      closeTailFile(state)
      state.currentKey = null
      return false
    }

    val newKey = readFileKey(path)
    openTailFileIfNeeded(path, newKey, state)
    val handle = state.raf ?: return false

    val len = runCatching { handle.length() }.getOrDefault(0L)
    if (len < state.pos) state.pos = 0L // truncation
    if (len <= state.pos) return false

    handle.seek(state.pos)
    val toRead = (len - state.pos).coerceAtMost(TAIL_READ_CHUNK.toLong()).toInt()
    val buf = ByteArray(toRead)
    val r = runCatching { handle.read(buf) }.getOrDefault(-1)
    if (r <= 0) return false

    state.pos += r
    emitTailText(state, String(buf, 0, r, StandardCharsets.UTF_8))
    return true
  }

  private fun readFileKey(path: Path): Any? =
    try {
      Files.readAttributes(path, BasicFileAttributes::class.java).fileKey()
    } catch (_: Throwable) {
      null
    }

  private fun openTailFileIfNeeded(path: Path, newKey: Any?, state: TailState) {
    if (
      state.raf == null ||
        (state.currentKey != null && newKey != null && state.currentKey != newKey)
    ) {
      // Open (or re-open after rotation). Start from end to avoid dumping historical logs.
      closeTailFile(state)
      val opened = RandomAccessFile(path.toFile(), "r")
      state.raf = opened
      state.currentKey = newKey
      state.pos = runCatching { opened.length() }.getOrDefault(0L)
    }
  }

  private fun emitTailText(state: TailState, text: String) {
    val parts = text.split('\n')
    if (parts.size == 1) {
      state.leftover.append(parts[0])
      return
    }

    val first = state.leftover.append(parts[0]).toString()
    if (first.isNotEmpty()) logLine(first)
    state.leftover = StringBuilder()
    for (i in 1 until parts.size - 1) logLine(parts[i])
    val last = parts.last()
    if (text.endsWith("\n")) logLine(last) else state.leftover.append(last)
  }

  private fun updateState(block: (AppState) -> AppState) {
    _state.value = block(_state.value)
  }

  private fun logLine(s: String) {
    // Non-suspending emission; when buffers are full, the oldest entries are dropped per
    // BufferOverflow.DROP_OLDEST.
    _logs.tryEmit(s)
  }

  private fun formatCommandForLog(cmd: List<String>): String {
    val isWindows = AppEnv().isWindows()
    return cmd.joinToString(" ") { arg ->
      if (isWindows) {
        if (arg.any { it.isWhitespace() || it == '"' }) {
          "\"" + arg.replace("\"", "\\\"") + "\""
        } else {
          arg
        }
      } else {
        if (arg.any { it.isWhitespace() || it == '\'' || it == '"' || it == '\\' }) {
          shellQuote(arg)
        } else {
          arg
        }
      }
    }
  }
}

internal fun ts(): String =
  java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_TIME)
