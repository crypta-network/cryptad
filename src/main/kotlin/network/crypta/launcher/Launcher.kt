package network.crypta.launcher

import java.awt.*
import java.awt.desktop.AppForegroundEvent
import java.awt.desktop.AppReopenedListener
import java.awt.desktop.QuitResponse
import java.awt.event.KeyEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import javax.swing.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collectLatest
import network.crypta.fs.AppEnv

/** Application display name used across the launcher UI and system integration. */
internal const val APP_NAME: String = "Crypta Launcher"

/**
 * Crypta Swing Launcher (View).
 *
 * MVC-style view that binds to [LauncherController.state] and [LauncherController.logs]. Keeps
 * keyboard shortcuts and UI behavior identical to the original implementation.
 */
class CryptaLauncher : JFrame(APP_NAME) {
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

  // Global key dispatcher to ensure shortcuts work even when the text area has focus
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
    registerLauncherInstance(this)
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

    // (no post-construct debug checks)

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
    // stop the wrapper first but trigger our quit sequence on close requests.
    addWindowListener(
      object : WindowAdapter() {
        override fun windowClosing(e: WindowEvent?) {
          if (AppEnv().isMac()) {
            // On macOS, close should only hide the window, not quit the app.
            isVisible = false
          } else {
            // On Linux/Windows, close should quit and stop the wrapper.
            quitApp()
          }
        }
      }
    )

    // Handle macOS Command+Q (app quit). Use the Desktop quit handler to route through our
    // shutdown.
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
        } catch (t: Throwable) {
          logDebug("Desktop About handler not available", t)
        }

        // Ensure clicking the Dock icon on macOS re-shows the window if hidden.
        try {
          d.addAppEventListener(
            AppReopenedListener {
              SwingUtilities.invokeLater {
                if (!isVisible) isVisible = true
                toFront()
                requestFocus()
              }
            }
          )
          d.addAppEventListener(
            object : java.awt.desktop.AppForegroundListener {
              override fun appRaisedToForeground(e: AppForegroundEvent?) {
                SwingUtilities.invokeLater {
                  if (!isVisible) isVisible = true
                  toFront()
                }
              }

              override fun appMovedToBackground(e: AppForegroundEvent?) {
                // Intentionally no-op: do not auto-hide or dispose when moved to the background.
                // Keeping the current window state avoids flickering and preserves any in-flight
                // start/stop interactions initiated by the user.
              }
            }
          )
        } catch (t: Throwable) {
          logDebug("Desktop event listeners not available", t)
        }
      }
    } catch (t: Throwable) {
      logDebug("Desktop integration initialization failed", t)
    }

    // Track manual scroll: disable auto-scroll when the user scrolls away from the bottom
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
          if (st.knownPort != null) {
            "Open http://localhost:${st.knownPort}/ in your browser"
          } else {
            "Open http://localhost:<port>/ in your browser"
          }
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
      // Wait for the wrapper to exit before quitting the launcher
      controller.shutdownAndWait()
      try {
        KeyboardFocusManager.getCurrentKeyboardFocusManager()
          .removeKeyEventDispatcher(globalDispatcher)
      } catch (t: Throwable) {
        logDebug("Failed to remove global key dispatcher", t)
      }
      dispose()
      uiScope.cancel()
      try {
        ThemeSwitcher.shutdown()
      } catch (t: Throwable) {
        logDebug("ThemeSwitcher.shutdown() failed", t)
      }
      kotlin.system.exitProcess(0)
    }
  }

  private fun showAboutDialog() {
    val dialog = JDialog(this, "About $APP_NAME", true)
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

    val title = JLabel(APP_NAME).apply { font = font.deriveFont(Font.BOLD, 20f) }
    right.add(title, gbc)

    val javaVer = System.getProperty("java.runtime.version") ?: System.getProperty("java.version")
    val env = AppEnv()
    val os = env.osNameRaw() + " " + env.osVersionRaw()
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
    } catch (t: Throwable) {
      logDebug("shutdownFromSignal(): controller shutdown failed", t)
    }
    try {
      ThemeSwitcher.shutdown()
    } catch (t: Throwable) {
      logDebug("shutdownFromSignal(): ThemeSwitcher.shutdown() failed", t)
    }
  }

  /** Public entry to initiate the normal quit flow from OS events (Windows hooks, etc.). */
  fun requestQuitFromOs() {
    SwingUtilities.invokeLater { quitApp() }
  }
}

/**
 * Application entry point.
 *
 * Installs FlatLaf as the Swing Look & Feel (macOS‑optimized theme on macOS, Flat Light elsewhere)
 * before creating any Swing components.
 */
fun main() {
  applyMacAppMenuName()
  installLookAndFeelWithFallback()
  SwingUtilities.invokeLater { createAndShowLauncherUi() }
  registerJvmShutdownHook()
  // Rely on the JVM shutdown hook; external TERM will trigger it.
}

/** Set the macOS application menu name early, before any AWT/Swing initialization. */
private fun applyMacAppMenuName() {
  try {
    System.setProperty("apple.awt.application.name", APP_NAME)
    System.setProperty("com.apple.mrj.application.apple.menu.about.name", APP_NAME)
  } catch (e: Exception) {
    logDebug("Failed to set macOS app menu name", e)
  }
}

/**
 * Install FlatLaf using ThemeSwitcher. If installation fails, fall back to the system look and feel
 * only when FlatLaf is not already active.
 */
private fun installLookAndFeelWithFallback() {
  try {
    ThemeSwitcher.install()
  } catch (e: Exception) {
    logWarn("FlatLaf installation failed; falling back to system LAF", e)
    try {
      val cur = UIManager.getLookAndFeel()
      val alreadyFlat = cur != null && cur.javaClass.name.startsWith("com.formdev.flatlaf")
      if (!alreadyFlat) UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
    } catch (t: Exception) {
      logDebug("Failed to set system Look&Feel after FlatLaf failure", t)
    }
  }
}

/** Create, size, iconize, show the launcher frame, and install platform-specific hooks. */
private fun createAndShowLauncherUi() {
  val f = CryptaLauncher()
  setWindowAndDockIcons(f)
  centerAndShow(f, Dimension(900, 600))
  installWindowsHooksIfNeeded(f)
}

private fun registerLauncherInstance(launcher: CryptaLauncher) {
  CryptaLauncher.instance = launcher
}

private fun setWindowAndDockIcons(f: JFrame) {
  try {
    val img = loadAppIconImage()
    if (img != null) {
      f.iconImage = img
      try {
        val tb = Taskbar.getTaskbar()
        if (tb.isSupported(Taskbar.Feature.ICON_IMAGE)) tb.iconImage = img
      } catch (t: Throwable) {
        logDebug("Failed to set Taskbar icon image", t)
      }
    }
  } catch (t: Throwable) {
    logDebug("Failed to load or set window icon", t)
  }
}

private fun centerAndShow(f: JFrame, size: Dimension) {
  val screen = Toolkit.getDefaultToolkit().screenSize
  f.size = size
  f.setLocation((screen.width - size.width) / 2, (screen.height - size.height) / 2)
  f.isVisible = true
}

/** Install Windows-specific message hooks (WM_QUERYENDSESSION/WM_ENDSESSION/WM_CLOSE). */
private fun installWindowsHooksIfNeeded(f: CryptaLauncher) {
  try {
    if (AppEnv().isWindows()) {
      WindowsMessageHooks.install(f) { f.requestQuitFromOs() }
    }
  } catch (t: Throwable) {
    logDebug("Windows message hook installation failed", t)
  }
}

/** Ensure a graceful shutdown on signals (e.g., CTRL+C forwarded by launcher script). */
private fun registerJvmShutdownHook() {
  try {
    Runtime.getRuntime()
      .addShutdownHook(
        Thread {
          try {
            CryptaLauncher.instance?.shutdownFromSignal()
          } catch (t: Throwable) {
            logDebug("Shutdown hook failed during shutdownFromSignal()", t)
          }
        }
      )
  } catch (t: Throwable) {
    logDebug("Failed to register JVM shutdown hook", t)
  }
}
