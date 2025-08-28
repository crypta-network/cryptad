package network.crypta.launcher

import java.awt.BorderLayout
import java.awt.Desktop
import java.awt.Dimension
import java.awt.Font
import java.awt.KeyEventDispatcher
import java.awt.KeyboardFocusManager
import java.awt.Toolkit
import java.awt.event.ActionEvent
import java.awt.event.KeyEvent
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import javax.swing.AbstractAction
import javax.swing.Action
import javax.swing.JButton
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollBar
import javax.swing.JScrollPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.WindowConstants
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Crypta Swing Launcher.
 *
 * Starts and stops the local `cryptad` script living next to this launcher's start script. Streams
 * combined stdout+stderr from the daemon and exposes keyboard shortcuts for quick control.
 */
class CryptaLauncher : JFrame("Crypta Launcher") {
  private val startStopBtn = JButton("Start")
  private val launchBtn = JButton("Launch in Browser")
  private val quitBtn = JButton("Quit")

  private val logArea =
    JTextArea().apply {
      font = Font(Font.MONOSPACED, Font.PLAIN, 12)
      isEditable = false
      lineWrap = false
      wrapStyleWord = false
    }
  private val scrollPane = JScrollPane(logArea)
  private val statusLabel =
    JLabel("↑/↓ row, PgUp/PgDn page, ←/→ focus buttons, Enter/Space click, q quit, s start/stop")

  // Process state
  @Volatile private var process: Process? = null
  @Volatile private var running: Boolean = false
  @Volatile private var knownPort: Int? = null
  @Volatile private var autoOpenedBrowserOnce: Boolean = false
  @Volatile private var shuttingDown: Boolean = false
  @Volatile private var stopping: Boolean = false
  private val uiScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
  private val shutdownScope: CoroutineScope = CoroutineScope(SupervisorJob())
  @Volatile private var tailJob: kotlinx.coroutines.Job? = null

  // Auto-scroll tracking
  @Volatile private var autoScrollEnabled: Boolean = true

  // Port line regex (tolerates IPv4/IPv6 and comma-separated addresses):
  // Capture the digits after the last ':' on the line.
  private val fproxyRegex =
    Regex("""Starting\s+FProxy\s+on\s+.*:(\d{2,5})(?:\s*|$)""", RegexOption.IGNORE_CASE)

  // Global key dispatcher to ensure shortcuts work even when text area has focus
  private val globalDispatcher = KeyEventDispatcher { e ->
    if (e.id != KeyEvent.KEY_PRESSED) return@KeyEventDispatcher false
    when (e.keyCode) {
      KeyEvent.VK_LEFT -> {
        cycleFocus(-1)
        e.consume()
        return@KeyEventDispatcher true
      }
      KeyEvent.VK_RIGHT -> {
        cycleFocus(+1)
        e.consume()
        return@KeyEventDispatcher true
      }
      KeyEvent.VK_S -> {
        if (!shuttingDown) {
          if (!running) startCryptad() else if (!stopping) stopCryptadAsync()
        }
        e.consume()
        return@KeyEventDispatcher true
      }
      KeyEvent.VK_Q -> {
        quitApp()
        e.consume()
        return@KeyEventDispatcher true
      }
      // Do not intercept ENTER/SPACE to avoid double-activating Swing buttons
      KeyEvent.VK_UP -> {
        scrollRows(-1)
        e.consume()
        return@KeyEventDispatcher true
      }
      KeyEvent.VK_DOWN -> {
        scrollRows(+1)
        e.consume()
        return@KeyEventDispatcher true
      }
      KeyEvent.VK_PAGE_UP -> {
        scrollPage(-1)
        e.consume()
        return@KeyEventDispatcher true
      }
      KeyEvent.VK_PAGE_DOWN -> {
        scrollPage(+1)
        e.consume()
        return@KeyEventDispatcher true
      }
    }
    false
  }

  init {
    defaultCloseOperation = WindowConstants.DO_NOTHING_ON_CLOSE
    minimumSize = Dimension(900, 600)
    layout = BorderLayout()

    // Top row: buttons
    val top = JPanel()
    startStopBtn.toolTipText = "Start or stop the Crypta daemon"
    launchBtn.toolTipText = "Open http://localhost:<port>/ in your browser"
    quitBtn.toolTipText = "Quit the launcher"
    launchBtn.isEnabled = false

    top.add(startStopBtn)
    top.add(launchBtn)
    top.add(quitBtn)

    add(top, BorderLayout.NORTH)
    add(scrollPane, BorderLayout.CENTER)
    add(statusLabel, BorderLayout.SOUTH)

    // Wire actions
    startStopBtn.addActionListener { if (!running) startCryptad() else stopCryptadAsync() }
    launchBtn.addActionListener { launchBrowser() }
    quitBtn.addActionListener { quitApp() }

    // Keyboard shortcuts through a global dispatcher (avoid root-pane bindings to prevent
    // duplicates)
    KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(globalDispatcher)

    // Track manual scroll: disable auto-scroll when the user scrolls away from bottom
    val vbar: JScrollBar = scrollPane.verticalScrollBar
    vbar.addAdjustmentListener { autoScrollEnabled = isAtBottom() }

    // Auto-start
    SwingUtilities.invokeLater { startCryptad() }
  }

  private fun isAtBottom(): Boolean {
    val vbar = scrollPane.verticalScrollBar
    // Within a small threshold from the bottom counts as bottom
    return vbar.value + vbar.visibleAmount >= vbar.maximum - 5
  }

  private fun appendLog(line: String) {
    SwingUtilities.invokeLater {
      val wasAtBottom = isAtBottom()
      logArea.append(line)
      logArea.append("\n")
      if (autoScrollEnabled && wasAtBottom) {
        logArea.caretPosition = logArea.document.length
      }
    }
  }

  private fun setRunning(value: Boolean) {
    running = value
    SwingUtilities.invokeLater {
      startStopBtn.text = if (value) "Stop" else "Start"
      startStopBtn.isEnabled = !shuttingDown
      launchBtn.isEnabled = value && knownPort != null && !shuttingDown
    }
  }

  private fun startCryptad() {
    if (running || process?.isAlive == true) return
    val cryptadPath = resolveCryptadPath()
    if (!Files.isRegularFile(cryptadPath) || !Files.isExecutable(cryptadPath)) {
      appendLog(ts() + " ERROR: Cannot find executable 'cryptad' at $cryptadPath")
      return
    }
    try {
      appendLog(ts() + " Starting '" + cryptadPath.fileName + "' ...")
      startStopBtn.isEnabled = false
      knownPort = null
      launchBtn.isEnabled = false

      val pb = buildProcess(cryptadPath)
      pb.redirectErrorStream(true)
      pb.directory(Paths.get(System.getProperty("user.dir")).toFile())
      val p = pb.start()
      process = p
      setRunning(true)

      // Reader coroutine: consume combined output, parse port
      uiScope.launch(Dispatchers.IO) { readProcessOutput(p) }

      // Watcher coroutine: wait for termination
      uiScope.launch(Dispatchers.IO) { watchProcess(p) }

      // Try to tail wrapper log file if present (helps when wrapper buffers JVM output)
      tailJob?.cancel()
      guessWrapperLogFile(cryptadPath)?.let { logPath ->
        tailJob = uiScope.launch(Dispatchers.IO) { tailFile(logPath) }
      }
    } catch (t: Throwable) {
      appendLog(ts() + " ERROR: Failed to start 'cryptad': ${t.message}")
      setRunning(false)
    } finally {
      startStopBtn.isEnabled = true
    }
  }

  private fun resolveCryptadPath(): Path {
    // Per requirements: resolve relative to current working directory
    val cwd = Paths.get(System.getProperty("user.dir"))
    return cwd.resolve("cryptad")
  }

  // On Unix, if `script` is available, run under a PTY to reduce buffering; otherwise run directly.
  private fun buildProcess(cryptadPath: Path): ProcessBuilder {
    val os = System.getProperty("os.name").lowercase()
    if (!os.contains("win")) {
      val scriptCmd = findOnPath("script")
      if (scriptCmd != null) {
        // Use a portable invocation that works on BSD/macOS and Linux: script -q /dev/null sh -lc
        // <cmd>
        return ProcessBuilder(scriptCmd, "-q", "/dev/null", "sh", "-lc", cryptadPath.toString())
      }
    }
    return ProcessBuilder(cryptadPath.toString())
  }

  private fun findOnPath(cmd: String): String? {
    val path = System.getenv("PATH") ?: return null
    val sep = if (System.getProperty("os.name").lowercase().contains("win")) ";" else ":"
    path.split(sep).forEach { dir ->
      try {
        val f = Paths.get(dir).resolve(cmd)
        if (Files.isRegularFile(f) && Files.isExecutable(f)) return f.toString()
      } catch (_: Exception) {}
    }
    return null
  }

  // Heuristics to locate wrapper.conf and derive the wrapper.logfile path to tail.
  private fun guessWrapperLogFile(cryptadPath: Path): Path? {
    val scriptDir = cryptadPath.parent ?: return null
    val confDefault = scriptDir.resolve("../conf/wrapper.conf").normalize()
    val conf =
      when {
        Files.isRegularFile(confDefault) -> confDefault
        Files.isRegularFile(cryptadPath) -> parseConfFromScript(cryptadPath) ?: confDefault
        else -> confDefault
      }
    if (!Files.isRegularFile(conf)) return null
    val confDir = conf.parent
    var logfile = readProperty(conf, "wrapper.logfile")?.trim().orEmpty()
    if (logfile.isEmpty()) {
      // Upstream default
      logfile = "../logs/wrapper.log"
    }
    val p = Paths.get(logfile)
    return if (p.isAbsolute) p else confDir.resolve(p).normalize()
  }

  private fun parseConfFromScript(script: Path): Path? {
    return try {
      val lines = Files.readAllLines(script, StandardCharsets.UTF_8)
      val re1 = Regex("""CONF="([^"]*wrapper\.conf)"""")
      val re2 = Regex("""-c\s+"([^"]*wrapper\.conf)"""")
      for (line in lines.take(200)) {
        re1.find(line)?.let { m ->
          return Paths.get(m.groupValues[1]).normalize()
        }
        re2.find(line)?.let { m ->
          return Paths.get(m.groupValues[1]).normalize()
        }
      }
      null
    } catch (_: Exception) {
      null
    }
  }

  private fun readProperty(conf: Path, key: String): String? {
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
    } catch (_: Exception) {}
    return null
  }

  private suspend fun tailFile(path: Path) {
    // Start reading from current end, then stream new data
    var pos = 0L
    var leftover = StringBuilder()
    while (process?.isAlive == true && !shuttingDown) {
      try {
        if (!Files.exists(path)) {
          delay(200)
          continue
        }
        java.io.RandomAccessFile(path.toFile(), "r").use { raf ->
          val len = raf.length()
          if (pos == 0L) pos = len // start at end to avoid dumping huge history
          if (len < pos) pos = 0L // rotated or truncated
          if (len > pos) {
            raf.seek(pos)
            val toRead = (len - pos).coerceAtMost(64 * 1024)
            val buf = ByteArray(toRead.toInt())
            val r = raf.read(buf)
            if (r > 0) {
              pos += r
              val text = String(buf, 0, r, StandardCharsets.UTF_8)
              val parts = text.split("\n")
              if (parts.size == 1) {
                leftover.append(parts[0])
              } else {
                // complete first line
                leftover.append(parts[0])
                appendLog(leftover.toString())
                leftover = StringBuilder()
                // middle lines
                for (i in 1 until parts.size - 1) appendLog(parts[i])
                // last partial
                leftover.append(parts.last())
              }
            }
          }
        }
      } catch (_: Exception) {
        // Ignore transient issues (rotation), retry
      }
      delay(200)
    }
  }

  private fun readProcessOutput(p: Process) {
    BufferedReader(InputStreamReader(p.inputStream, StandardCharsets.UTF_8)).use { br ->
      while (true) {
        val line = br.readLine() ?: break
        appendLog(line)

        if (knownPort == null) {
          var port: Int? = fproxyRegex.find(line)?.groupValues?.getOrNull(1)?.toIntOrNull()
          if (
            port == null &&
              line.contains("Starting", ignoreCase = true) &&
              line.contains("FProxy", ignoreCase = true) &&
              line.contains("on ", ignoreCase = true)
          ) {
            // Fallback: take digits after the final ':' if the line ends with ":<port>"
            val idx = line.lastIndexOf(':')
            if (idx > 0 && idx + 1 < line.length) {
              val tail = line.substring(idx + 1).trim()
              if (tail.all { it.isDigit() } && tail.length in 2..5) {
                port = tail.toIntOrNull()
              }
            }
          }
          if (port != null) {
            knownPort = port
            SwingUtilities.invokeLater { launchBtn.isEnabled = running && !shuttingDown }
            if (!autoOpenedBrowserOnce) {
              autoOpenedBrowserOnce = true
              SwingUtilities.invokeLater { launchBrowser() }
            }
          }
        }
      }
    }
  }

  private fun watchProcess(p: Process) {
    val exit =
      try {
        p.waitFor()
      } catch (_: InterruptedException) {
        return
      }
    appendLog(ts() + " cryptad exited with code $exit")
    process = null
    setRunning(false)
  }

  private fun stopCryptadAsync() {
    val p = process ?: return
    if (!p.isAlive) {
      setRunning(false)
      return
    }
    if (stopping) return
    stopping = true
    SwingUtilities.invokeLater {
      startStopBtn.isEnabled = false
      launchBtn.isEnabled = false
    }
    uiScope.launch {
      try {
        withContext(Dispatchers.IO) { stopCryptadBlocking(p) }
      } finally {
        stopping = false
        startStopBtn.isEnabled = true
      }
    }
  }

  private fun stopCryptadBlocking(p: Process) {
    try {
      val pid = p.pid()
      appendLog(ts() + " Sending SIGINT to PID $pid ...")
      val isWindows = System.getProperty("os.name").lowercase().contains("win")
      val ok = if (isWindows) killWindows(pid) else killUnix(pid)
      if (!ok) {
        appendLog(ts() + " WARN: Could not send graceful signal; destroying process ...")
        p.destroy()
      }

      // Await exit up to 20 seconds
      val deadline = System.nanoTime() + 20_000_000_000L
      while (p.isAlive && System.nanoTime() < deadline) {
        try {
          Thread.sleep(200)
        } catch (_: InterruptedException) {}
      }
      if (p.isAlive) {
        appendLog(ts() + " Forcibly terminating PID $pid ...")
        p.destroyForcibly()
      }
    } catch (t: Throwable) {
      appendLog(ts() + " ERROR: Failed to stop process: ${t.message}")
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

  private fun launchBrowser() {
    val port = knownPort
    if (!running || port == null) return
    val uri = URI.create("http://localhost:$port/")
    Thread(
        {
          try {
            if (Desktop.isDesktopSupported()) {
              val d = Desktop.getDesktop()
              if (d.isSupported(Desktop.Action.BROWSE)) {
                d.browse(uri)
                return@Thread
              }
            }
            // Fallbacks by OS
            val os = System.getProperty("os.name").lowercase()
            if (os.contains("mac")) {
              ProcessBuilder("open", uri.toString()).start()
            } else if (os.contains("win")) {
              ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", uri.toString()).start()
            } else {
              ProcessBuilder("xdg-open", uri.toString()).start()
            }
          } catch (t: Throwable) {
            appendLog(ts() + " ERROR: Failed to launch browser: ${t.message}")
          }
        },
        "browser-launcher",
      )
      .start()
  }

  private fun quitApp() {
    if (shuttingDown) return
    shuttingDown = true
    startStopBtn.isEnabled = false
    launchBtn.isEnabled = false
    quitBtn.isEnabled = false
    // Try to stop daemon in background, but do not block app exit
    process?.let { p ->
      if (p.isAlive) {
        shutdownScope.launch(Dispatchers.IO) { stopCryptadBlocking(p) }
      }
    }
    // Exit shortly regardless to avoid UI hanging if daemon ignores signals
    shutdownScope.launch(Dispatchers.Main.immediate) {
      delay(200)
      try {
        KeyboardFocusManager.getCurrentKeyboardFocusManager()
          .removeKeyEventDispatcher(globalDispatcher)
      } catch (_: Throwable) {}
      try {
        dispose()
      } catch (_: Throwable) {}
      uiScope.cancel()
      shutdownScope.cancel()
      kotlin.system.exitProcess(0)
    }
  }

  // No root-pane InputMap/ActionMap bindings; globalDispatcher handles all shortcuts.

  private fun action(body: () -> Unit) =
    object : AbstractAction() {
      override fun actionPerformed(e: ActionEvent?) {
        body()
      }
    }

  private fun scrollRows(deltaRows: Int) {
    val fm = logArea.getFontMetrics(logArea.font)
    val pixels = fm.height * deltaRows
    val vbar = scrollPane.verticalScrollBar
    vbar.value = clamp(vbar.value + pixels, 0, vbar.maximum - vbar.visibleAmount)
  }

  private fun scrollPage(deltaPages: Int) {
    val vp = scrollPane.viewport
    val pixels = vp.extentSize.height * deltaPages
    val vbar = scrollPane.verticalScrollBar
    vbar.value = clamp(vbar.value + pixels, 0, vbar.maximum - vbar.visibleAmount)
  }

  private fun cycleFocus(direction: Int) {
    val buttons = listOf(startStopBtn, launchBtn, quitBtn)
    val focusOwner = KeyboardFocusManager.getCurrentKeyboardFocusManager().focusOwner
    val idx = buttons.indexOf(focusOwner)
    val next = if (idx == -1) 0 else (idx + direction + buttons.size) % buttons.size
    buttons[next].requestFocusInWindow()
  }

  private fun clickFocusedTopButton() {
    val buttons = listOf(startStopBtn, launchBtn, quitBtn)
    val focusOwner = KeyboardFocusManager.getCurrentKeyboardFocusManager().focusOwner
    buttons.firstOrNull { it === focusOwner }?.doClick()
  }

  private fun clamp(value: Int, min: Int, max: Int): Int = Math.max(min, Math.min(max, value))

  private fun ts(): String = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME)
}

/** Application entry point. */
fun main() {
  // Native look & feel
  try {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
  } catch (_: Exception) {}

  SwingUtilities.invokeLater {
    val f = CryptaLauncher()
    // Center on screen
    val screen = Toolkit.getDefaultToolkit().screenSize
    val size = Dimension(900, 600)
    f.size = size
    f.setLocation((screen.width - size.width) / 2, (screen.height - size.height) / 2)
    f.isVisible = true
  }
}
