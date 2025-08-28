package network.crypta.launcher

import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Font
import java.awt.KeyEventDispatcher
import java.awt.KeyboardFocusManager
import java.awt.Toolkit
import java.awt.event.KeyEvent
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
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

/**
 * Crypta Swing Launcher (View).
 *
 * MVC-style view that binds to [LauncherController.state] and [LauncherController.logs]. Keeps
 * keyboard shortcuts and UI behavior identical to the original implementation.
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
    startStopBtn.addActionListener {
      val st = controller.state.value
      if (st.isRunning) controller.stop() else controller.start()
    }
    launchBtn.addActionListener { controller.launchBrowser() }
    quitBtn.addActionListener { quitApp() }

    // Keyboard shortcuts through a global dispatcher (avoid root-pane bindings to prevent
    // duplicates)
    KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(globalDispatcher)

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

  private fun clamp(value: Int, min: Int, max: Int): Int = Math.max(min, Math.min(max, value))

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
      kotlin.system.exitProcess(0)
    }
  }
}

/** Application entry point. */
fun main() {
  try {
    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
  } catch (_: Exception) {}

  SwingUtilities.invokeLater {
    val f = CryptaLauncher()
    val screen = Toolkit.getDefaultToolkit().screenSize
    val size = Dimension(900, 600)
    f.size = size
    f.setLocation((screen.width - size.width) / 2, (screen.height - size.height) / 2)
    f.isVisible = true
  }
}
