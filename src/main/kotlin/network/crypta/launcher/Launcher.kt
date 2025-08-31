package network.crypta.launcher

import java.awt.*
import java.awt.desktop.QuitResponse
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest

/**
 * Crypta Swing Launcher (View).
 *
 * MVC-style view that binds to [LauncherController.state] and [LauncherController.logs]. Keeps
 * keyboard shortcuts and UI behavior identical to the original implementation.
 */
class CryptaLauncher : JFrame("Crypta Launcher") {
  companion object {
    @Volatile var instance: CryptaLauncher? = null
  }

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

  private val uiScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
  private val controller = LauncherController(uiScope)

  // Auto-scroll tracking
  @Volatile private var autoScrollEnabled: Boolean = true

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
        val st = controller.state.value
        if (st.isStoppingOrShuttingDown) return@KeyEventDispatcher true
        if (st.isRunning) controller.stop() else controller.start()
        e.consume()
        return@KeyEventDispatcher true
      }
      KeyEvent.VK_Q -> {
        quitApp()
        e.consume()
        return@KeyEventDispatcher true
      }
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
    instance = this
    defaultCloseOperation = DO_NOTHING_ON_CLOSE
    // Allow shrinking to half of the default size
    minimumSize = Dimension(450, 300)
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
    startStopBtn.addActionListener {
      val st = controller.state.value
      if (st.isRunning) controller.stop() else controller.start()
    }
    launchBtn.addActionListener { controller.launchBrowser() }
    quitBtn.addActionListener { quitApp() }

    // Keyboard shortcuts through a global dispatcher (avoid root-pane bindings to prevent
    // duplicates)
    KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(globalDispatcher)

    // Handle window manager close button (e.g., Ubuntu). We keep DO_NOTHING to ensure we can
    // stop the wrapper first, but trigger our quit sequence on close requests.
    addWindowListener(
      object : WindowAdapter() {
        override fun windowClosing(e: WindowEvent?) {
          val os = System.getProperty("os.name").lowercase()
          if (os.contains("mac")) {
            // On macOS, close should only hide the window, not quit the app.
            isVisible = false
          } else {
            // On Linux/Windows, close should quit and stop the wrapper.
            quitApp()
          }
        }
      }
    )

    // Handle macOS Command+Q (app quit). Use Desktop quit handler to route through our shutdown.
    try {
      if (Desktop.isDesktopSupported()) {
        val d = Desktop.getDesktop()
        // If unsupported on this platform, setQuitHandler will throw; guard with try/catch.
        d.setQuitHandler { _, response: QuitResponse ->
          // Defer default quit until we've stopped the wrapper cleanly.
          response.cancelQuit()
          SwingUtilities.invokeLater { quitApp() }
        }

        // Custom About dialog (macOS system menu About handler)
        try {
          d.setAboutHandler { SwingUtilities.invokeLater { showAboutDialog() } }
        } catch (_: Throwable) {}

        // Ensure clicking the Dock icon on macOS re-shows the window if hidden.
        try {
          d.addAppEventListener(
            object : java.awt.desktop.AppReopenedListener {
              override fun appReopened(e: java.awt.desktop.AppReopenedEvent?) {
                SwingUtilities.invokeLater {
                  if (!isVisible) isVisible = true
                  toFront()
                  requestFocus()
                }
              }
            }
          )
          d.addAppEventListener(
            object : java.awt.desktop.AppForegroundListener {
              override fun appRaisedToForeground(e: java.awt.desktop.AppForegroundEvent?) {
                SwingUtilities.invokeLater {
                  if (!isVisible) isVisible = true
                  toFront()
                }
              }

              override fun appMovedToBackground(e: java.awt.desktop.AppForegroundEvent?) {}
            }
          )
        } catch (_: Throwable) {}
      }
    } catch (_: Throwable) {}

    // Track manual scroll: disable auto-scroll when the user scrolls away from bottom
    val vbar: JScrollBar = scrollPane.verticalScrollBar
    vbar.addAdjustmentListener { autoScrollEnabled = isAtBottom() }

    // Bind logs
    uiScope.launch { controller.logs.collectLatest { appendLog(it) } }

    // Bind state
    uiScope.launch {
      controller.state.collect { st ->
        startStopBtn.text = if (st.isRunning) "Stop" else "Start"
        startStopBtn.isEnabled = !st.isShuttingDown
        launchBtn.isEnabled = st.isRunning && st.knownPort != null && !st.isShuttingDown
        // Update tooltip with actual port when known
        launchBtn.toolTipText =
          if (st.knownPort != null) "Open http://localhost:${st.knownPort}/ in your browser"
          else "Open http://localhost:<port>/ in your browser"
      }
    }

    // Auto-start
    SwingUtilities.invokeLater { controller.start() }
  }

  private fun isAtBottom(): Boolean {
    val vbar = scrollPane.verticalScrollBar
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

  private fun scrollRows(deltaRows: Int) {
    val fm = logArea.getFontMetrics(logArea.font)
    val pixels = fm.height * deltaRows
    val vbar = scrollPane.verticalScrollBar
    val upper = (vbar.maximum - vbar.visibleAmount).coerceAtLeast(0)
    vbar.value = (vbar.value + pixels).coerceIn(0, upper)
  }

  private fun scrollPage(deltaPages: Int) {
    val vp = scrollPane.viewport
    val pixels = vp.extentSize.height * deltaPages
    val vbar = scrollPane.verticalScrollBar
    val upper = (vbar.maximum - vbar.visibleAmount).coerceAtLeast(0)
    vbar.value = (vbar.value + pixels).coerceIn(0, upper)
  }

  private fun cycleFocus(direction: Int) {
    val buttons = listOf(startStopBtn, launchBtn, quitBtn)
    val focusOwner = KeyboardFocusManager.getCurrentKeyboardFocusManager().focusOwner
    val idx = buttons.indexOf(focusOwner)
    val next = if (idx == -1) 0 else (idx + direction + buttons.size) % buttons.size
    buttons[next].requestFocusInWindow()
  }

  private fun quitApp() {
    // Disable UI while quitting
    startStopBtn.isEnabled = false
    launchBtn.isEnabled = false
    quitBtn.isEnabled = false
    uiScope.launch {
      // Wait for wrapper to exit before quitting the launcher
      controller.shutdownAndWait()
      try {
        KeyboardFocusManager.getCurrentKeyboardFocusManager()
          .removeKeyEventDispatcher(globalDispatcher)
      } catch (_: Throwable) {}
      dispose()
      uiScope.cancel()
      try {
        ThemeSwitcher.shutdown()
      } catch (_: Throwable) {}
      kotlin.system.exitProcess(0)
    }
  }

  private fun showAboutDialog() {
    val dialog = JDialog(this, "About Crypta Launcher", true)
    dialog.layout = BorderLayout(12, 12)
    val content = JPanel(BorderLayout(12, 12))
    content.border = BorderFactory.createEmptyBorder(16, 16, 16, 16)

    // Left icon
    val iconLabel =
      JLabel().also { lbl ->
        loadAppIconImage()?.let { img ->
          val size = 96
          val scaled = img.getScaledInstance(size, size, Image.SCALE_SMOOTH)
          lbl.icon = ImageIcon(scaled)
        }
      }
    content.add(iconLabel, BorderLayout.WEST)

    // Right info column (compact, predictable width)
    val right = JPanel(GridBagLayout())
    val gbc =
      GridBagConstraints().apply {
        gridx = 0
        fill = GridBagConstraints.HORIZONTAL
        anchor = GridBagConstraints.FIRST_LINE_START
        weightx = 1.0
        insets = Insets(0, 0, 6, 0)
      }

    val title = JLabel("Crypta Launcher").apply { font = font.deriveFont(Font.BOLD, 20f) }
    right.add(title, gbc)

    val javaVer = System.getProperty("java.runtime.version") ?: System.getProperty("java.version")
    val os = System.getProperty("os.name") + " " + (System.getProperty("os.version") ?: "")
    val build = runCatching { network.crypta.node.currentBuildNumber() }.getOrDefault(0)
    val git =
      runCatching {
          network.crypta.node.gitRevision().let { rev ->
            if (rev.startsWith("@") && rev.endsWith("@")) "unknown" else rev.take(12)
          }
        }
        .getOrDefault("unknown")

    val infoFont = UIManager.getFont("Label.font").deriveFont(13f)
    val row1 =
      JPanel(FlowLayout(FlowLayout.LEFT, 12, 0)).apply {
        add(JLabel("Build: $build").apply { font = infoFont })
        add(JLabel("Git: $git").apply { font = infoFont })
      }
    val row2 =
      JPanel(FlowLayout(FlowLayout.LEFT, 12, 0)).apply {
        add(JLabel("Java: $javaVer").apply { font = infoFont })
        add(JLabel("OS: $os").apply { font = infoFont })
      }
    gbc.gridy = 1
    right.add(row1, gbc)
    gbc.gridy = 2
    right.add(row2, gbc)

    gbc.gridy = 3
    right.add(JLabel("© 2025 Crypta contributors").apply { font = infoFont }, gbc)

    // GPLv3 license text in a wrapping area with a fixed column width
    val license =
      JTextArea().apply {
        isEditable = false
        isOpaque = false
        lineWrap = true
        wrapStyleWord = true
        columns = 48
        rows = 4
        font = UIManager.getFont("Label.font")
        text =
          "Crypta Launcher is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License version 3 (GPLv3) only.\n" +
            "This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE file or https://www.gnu.org/licenses/gpl-3.0.html."
      }
    gbc.gridy = 4
    right.add(license, gbc)

    content.add(right, BorderLayout.CENTER)

    val btn = JButton("OK")
    btn.addActionListener { dialog.dispose() }
    dialog.rootPane.defaultButton = btn
    val south = JPanel(FlowLayout(FlowLayout.RIGHT))
    south.add(btn)

    dialog.add(content, BorderLayout.CENTER)
    dialog.add(south, BorderLayout.SOUTH)
    dialog.pack()
    dialog.setLocationRelativeTo(this)
    dialog.isResizable = false
    dialog.isVisible = true
  }

  /** Called from JVM shutdown hook (e.g., SIGINT) to stop wrapper gracefully. */
  fun shutdownFromSignal() {
    try {
      runBlocking { controller.shutdownAndWait() }
    } catch (_: Throwable) {}
    try {
      ThemeSwitcher.shutdown()
    } catch (_: Throwable) {}
  }
}

/**
 * Application entry point.
 *
 * Installs FlatLaf as the Swing Look & Feel (macOS‑optimized theme on macOS, Flat Light elsewhere)
 * before creating any Swing components.
 */
fun main() {
  // Set macOS application menu name before any AWT/Swing initialization
  try {
    System.setProperty("apple.awt.application.name", "Crypta Launcher")
    System.setProperty("com.apple.mrj.application.apple.menu.about.name", "Crypta Launcher")
  } catch (_: Exception) {}

  // Install FlatLaf with OS theme detection + live switching
  try {
    ThemeSwitcher.install()
  } catch (_: Exception) {
    try {
      UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
    } catch (_: Exception) {}
  }

  SwingUtilities.invokeLater {
    val f = CryptaLauncher()
    // Set icon for window and Dock (where supported)
    try {
      val img = loadAppIconImage()
      if (img != null) {
        f.iconImage = img
        try {
          val tb = Taskbar.getTaskbar()
          if (tb.isSupported(Taskbar.Feature.ICON_IMAGE)) tb.iconImage = img
        } catch (_: Throwable) {}
      }
    } catch (_: Throwable) {}
    val screen = Toolkit.getDefaultToolkit().screenSize
    val size = Dimension(900, 600)
    f.size = size
    f.setLocation((screen.width - size.width) / 2, (screen.height - size.height) / 2)
    f.isVisible = true
  }

  // Ensure graceful shutdown on signals (e.g., CTRL+C forwarded by launcher script)
  try {
    Runtime.getRuntime()
      .addShutdownHook(
        Thread {
          try {
            CryptaLauncher.instance?.shutdownFromSignal()
          } catch (_: Throwable) {}
        }
      )
  } catch (_: Throwable) {}

  // Rely on the JVM shutdown hook (above). External TERM will trigger it.
}
