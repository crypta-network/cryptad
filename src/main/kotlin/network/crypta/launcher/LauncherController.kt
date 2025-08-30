package network.crypta.launcher

import java.awt.Desktop
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.*

// Log buffering strategy
// - Keep a small replay window so late subscribers get recent lines
// - Cap extra capacity and drop the oldest entries under backpressure to stay memory-bounded
private const val LOG_REPLAY: Int = 200
private const val LOG_EXTRA_CAPACITY: Int = 300
private const val TAIL_BASE_DELAY_MS: Long = 200
private const val TAIL_MAX_DELAY_MS: Long = 1500
private const val TAIL_READ_CHUNK: Int = 64 * 1024

/** Controller for the Crypta launcher. Manages the daemon process and exposes state and logs. */
class LauncherController(
  private val scope: CoroutineScope,
  private val io: CoroutineDispatcher = Dispatchers.IO,
  private val cwd: Path = Paths.get(System.getProperty("user.dir")),
) {
  private val _state = MutableStateFlow(AppState())
  val state: StateFlow<AppState> = _state.stateIn(scope, SharingStarted.Eagerly, _state.value)

  /**
   * Bounded, drop-older log stream.
   *
   * We keep a small replay window so late subscribers (e.g., UI created after controller) still see
   * the latest lines, and we cap total in-memory buffering to avoid memory pressure when the daemon
   * is very chatty or the UI is momentarily stalled.
   *
   * Total buffer = [LOG_REPLAY] + [LOG_EXTRA_CAPACITY]. When full, the oldest entries are dropped.
   */
  private val _logs =
    MutableSharedFlow<String>(
      replay = LOG_REPLAY,
      extraBufferCapacity = LOG_EXTRA_CAPACITY,
      onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
  val logs: SharedFlow<String> = _logs.asSharedFlow()

  private var process: Process? = null
  private var tailJob: Job? = null
  private var autoOpenedBrowser = false
  // Separate shutdown scope so quit can proceed even if the UI scope is cancelled
  private val shutdownScope: CoroutineScope = CoroutineScope(SupervisorJob() + io)

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
          " exec: " + formatCommandForLog(cmd) + " (cwd=" + cwd.toAbsolutePath().toString() + ")"
      )
      val pb = ProcessBuilder(cmd)
      pb.redirectErrorStream(true)
      pb.directory(cwd.toFile())
      val p = pb.start()
      process = p

      // Reader: combined stdout+stderr
      scope.launch(io) { readProcessOutput(p) }
      // Watcher: termination
      scope.launch(io) { watchProcess(p) }
      // Tail wrapper.log if present
      tailJob?.cancel()
      guessWrapperConfPathForCryptadScript(cryptadPath)?.let { conf ->
        val logSpec = readWrapperProperty(conf, "wrapper.logfile")
        val logPath = computeWrapperLogPath(conf, logSpec)
        tailJob = scope.launch(io) { tailFileWhileAlive(logPath) }
      }
    }
  }

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
        val os = System.getProperty("os.name").lowercase()
        if (os.contains("mac")) {
          ProcessBuilder("open", uri.toString()).start()
        } else if (os.contains("win")) {
          ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", uri.toString()).start()
        } else {
          ProcessBuilder("xdg-open", uri.toString()).start()
        }
      } catch (t: Throwable) {
        logLine(ts() + " ERROR: Failed to launch browser: ${t.message}")
      }
    }
  }

  fun shutdown() {
    if (_state.value.isShuttingDown) return
    updateState { it.copy(isShuttingDown = true) }
    shutdownScope.launch { process?.let { p -> if (p.isAlive) stopProcessGracefully(p) } }
  }

  /**
   * Shutdown and suspend until the wrapper process has exited (or been force-killed). Safe to call
   * multiple times; subsequent calls return immediately.
   */
  suspend fun shutdownAndWait() {
    if (_state.value.isShuttingDown) {
      // If already shutting down, just wait until not running
      return withContext(io) {
        val p = process
        if (p != null && p.isAlive) stopProcessGracefully(p)
      }
    }
    updateState { it.copy(isShuttingDown = true) }
    withContext(io) { process?.let { p -> if (p.isAlive) stopProcessGracefully(p) } }
  }

  // --- internals ---

  private suspend fun readProcessOutput(p: Process) {
    withContext(io) {
      val br =
        java.io.BufferedReader(java.io.InputStreamReader(p.inputStream, StandardCharsets.UTF_8))
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

  private suspend fun tailFileWhileAlive(path: Path) {
    // Keep a single RAF open to avoid repeated open/close churn. Add exponential backoff when no
    // new data arrives to reduce filesystem pressure. Re-open on file rotation or truncation.
    withContext(io) {
      var raf: java.io.RandomAccessFile? = null
      var currentKey: Any? = null
      var pos = 0L
      var leftover = StringBuilder()
      var idleCount = 0 // consecutive loops without new data

      fun calcDelayMs(): Long {
        val shifts = idleCount.coerceAtMost(3) // 200, 400, 800, 1600ms
        val d = TAIL_BASE_DELAY_MS shl shifts
        return d.coerceAtMost(TAIL_MAX_DELAY_MS)
      }

      while (scope.isActive && (process?.isAlive == true)) {
        try {
          if (!Files.exists(path)) {
            raf?.close()
            raf = null
            currentKey = null
            idleCount++
            delay(calcDelayMs())
            continue
          }

          // Detect rotation by file key if available
          val newKey =
            try {
              Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java)
                .fileKey()
            } catch (_: Throwable) {
              null
            }

          if (raf == null || (currentKey != null && newKey != null && currentKey != newKey)) {
            // Open (or re-open after rotation). Start from end to avoid dumping historical logs.
            runCatching { raf?.close() }
            raf = java.io.RandomAccessFile(path.toFile(), "r")
            currentKey = newKey
            val len = runCatching { raf.length() }.getOrDefault(0L)
            pos = len
          }

          val handle = raf

          val len = runCatching { handle.length() }.getOrDefault(0L)
          if (len < pos) pos = 0L // truncation

          var madeProgress = false
          if (len > pos) {
            handle.seek(pos)
            val toRead = (len - pos).coerceAtMost(TAIL_READ_CHUNK.toLong()).toInt()
            val buf = ByteArray(toRead)
            val r = runCatching { handle.read(buf) }.getOrDefault(-1)
            if (r > 0) {
              pos += r
              val text = String(buf, 0, r, StandardCharsets.UTF_8)
              val parts = text.split('\n')
              if (parts.size == 1) {
                leftover.append(parts[0])
              } else {
                val first = leftover.append(parts[0]).toString()
                if (first.isNotEmpty()) logLine(first)
                leftover = StringBuilder()
                for (i in 1 until parts.size - 1) logLine(parts[i])
                val last = parts.last()
                if (text.endsWith("\n")) logLine(last) else leftover.append(last)
              }
              madeProgress = true
            }
          }

          if (madeProgress) idleCount = 0 else idleCount++
        } catch (_: Throwable) {
          // On any error, force re-open next loop.
          runCatching { raf?.close() }
          raf = null
          currentKey = null
          idleCount++
        }

        delay(calcDelayMs())
      }

      runCatching { raf?.close() }
    }
  }

  private suspend fun stopProcessGracefully(p: Process) {
    try {
      val pid = p.pid()
      val isWindows = System.getProperty("os.name").lowercase().contains("win")
      // Snapshot descendants before we start signaling to avoid losing them if the root dies early
      val snapshot = getDescendantTreePids(pid)
      val allPids = listOf(pid) + snapshot

      if (isWindows) {
        runCmd("cmd", "/c", "taskkill /PID $pid /T")
        if (!waitForPidsToExit(allPids, 20_000)) {
          runCmd("cmd", "/c", "taskkill /F /PID $pid /T")
          waitForPidsToExit(allPids, 5_000)
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

  private fun getDescendantTreePids(rootPid: Long): List<Long> {
    return try {
      val opt = ProcessHandle.of(rootPid)
      if (!opt.isPresent) emptyList()
      else {
        val root = opt.get()
        root
          .descendants()
          .map(java.util.function.Function<ProcessHandle, Long> { it.pid() })
          .toList()
      }
    } catch (_: Throwable) {
      emptyList()
    }
  }

  private fun isPidAlive(pid: Long): Boolean {
    return try {
      ProcessHandle.of(pid).map { it.isAlive }.orElse(false)
    } catch (_: Throwable) {
      false
    }
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
      } catch (_: Throwable) {}
    }
  }

  private fun runCmd(vararg args: String): Boolean =
    try {
      val pr = ProcessBuilder(*args).start()
      pr.waitFor() == 0
    } catch (_: Throwable) {
      false
    }

  private fun tryEnableConsoleFlush(cryptadPath: Path) {
    try {
      val conf = guessWrapperConfPathForCryptadScript(cryptadPath) ?: return
      if (!Files.isRegularFile(conf)) return
      val lines = Files.readAllLines(conf, StandardCharsets.UTF_8)
      val props = parseWrapperProperties(lines)
      if (props["wrapper.console.flush"]?.equals("TRUE", ignoreCase = true) == true) return
      val updated = upsertWrapperProperty(lines, "wrapper.console.flush", "TRUE")
      Files.write(conf, updated, StandardCharsets.UTF_8)
    } catch (_: Throwable) {
      // best-effort only
    }
  }

  private fun readWrapperProperty(conf: Path, key: String): String? =
    try {
      Files.newBufferedReader(conf, StandardCharsets.UTF_8).use { br ->
        while (true) {
          val raw = br.readLine() ?: break
          val line = raw.trim()
          if (line.isEmpty() || line.startsWith("#")) continue
          val idx = line.indexOf('=')
          if (idx <= 0) continue
          val k = line.substringBefore('=', "").trim()
          if (k == key) return line.substringAfter('=', "").trim()
        }
      }
      null
    } catch (_: Throwable) {
      null
    }

  private fun updateState(block: (AppState) -> AppState) {
    _state.value = block(_state.value)
  }

  private fun logLine(s: String) {
    // Non-suspending emission; when buffers are full the oldest entries are dropped per
    // BufferOverflow.DROP_OLDEST.
    _logs.tryEmit(s)
  }

  private fun formatCommandForLog(cmd: List<String>): String {
    val isWindows = System.getProperty("os.name").lowercase().contains("win")
    return cmd.joinToString(" ") { arg ->
      if (isWindows) {
        if (arg.any { it.isWhitespace() || it == '"' }) "\"" + arg.replace("\"", "\\\"") + "\""
        else arg
      } else {
        if (arg.any { it.isWhitespace() || it == '\'' || it == '"' || it == '\\' }) shellQuote(arg)
        else arg
      }
    }
  }
}

internal fun ts(): String =
  java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_TIME)
