package network.crypta.launcher

import java.awt.Desktop
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Controller for the Crypta launcher. Manages the daemon process and exposes state and logs. */
class LauncherController(
  private val scope: CoroutineScope,
  private val io: CoroutineDispatcher = Dispatchers.IO,
  private val cwd: Path = Paths.get(System.getProperty("user.dir")),
) {
  private val _state = MutableStateFlow(AppState())
  val state: StateFlow<AppState> = _state.stateIn(scope, SharingStarted.Eagerly, _state.value)

  private val _logs = MutableSharedFlow<String>(extraBufferCapacity = 1024)
  val logs = _logs.asSharedFlow()

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
    withContext(io) {
      var pos = 0L
      var leftover = StringBuilder()
      while (scope.isActive && (process?.isAlive == true)) {
        try {
          if (!Files.exists(path)) {
            delay(200)
            continue
          }
          java.io.RandomAccessFile(path.toFile(), "r").use { raf ->
            val len = raf.length()
            if (pos == 0L) pos = len
            if (len < pos) pos = 0L
            if (len > pos) {
              raf.seek(pos)
              val toRead = (len - pos).coerceAtMost(64 * 1024)
              val buf = ByteArray(toRead.toInt())
              val r = raf.read(buf)
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
              }
            }
          }
        } catch (_: Throwable) {
          // ignore tail errors
        }
        delay(200)
      }
    }
  }

  private suspend fun stopProcessGracefully(p: Process) {
    try {
      val pid = p.pid()
      logLine(ts() + " Sending SIGINT to PID $pid ...")
      val isWindows = System.getProperty("os.name").lowercase().contains("win")
      val ok = if (isWindows) killWindows(pid) else killUnix(pid)
      if (!ok) {
        logLine(ts() + " WARN: Could not send graceful signal; destroying process ...")
        p.destroy()
      }
      val deadline = System.nanoTime() + 20_000_000_000L
      while (p.isAlive && System.nanoTime() < deadline) {
        try {
          Thread.sleep(200)
        } catch (_: InterruptedException) {}
      }
      if (p.isAlive) {
        logLine(ts() + " Forcibly terminating PID $pid ...")
        p.destroyForcibly()
      }
    } catch (t: Throwable) {
      logLine(ts() + " ERROR: Failed to stop process: ${t.message}")
    }
  }

  private fun killUnix(pid: Long): Boolean =
    try {
      val sh = ProcessBuilder("sh", "-lc", "kill -INT $pid").start()
      sh.waitFor() == 0
    } catch (_: Throwable) {
      false
    }

  private fun killWindows(pid: Long): Boolean =
    try {
      val cmd = ProcessBuilder("cmd", "/c", "taskkill /PID $pid /T").start()
      cmd.waitFor() == 0
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
          val k = line.substring(0, idx).trim()
          if (k == key) return line.substring(idx + 1).trim()
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
    _logs.tryEmit(s)
  }
}

internal fun ts(): String =
  java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ISO_LOCAL_TIME)
