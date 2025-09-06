package network.crypta.launcher

import com.sun.jna.Native
import com.sun.jna.CallbackReference
import com.sun.jna.Pointer
import com.sun.jna.platform.WindowUtils
import com.sun.jna.platform.win32.User32
import com.sun.jna.platform.win32.W32APIOptions
import com.sun.jna.platform.win32.WinDef.HWND
import com.sun.jna.platform.win32.WinDef.LRESULT
import com.sun.jna.platform.win32.WinDef.LPARAM
import com.sun.jna.platform.win32.WinDef.WPARAM
import com.sun.jna.platform.win32.WinUser
import javax.swing.JFrame
import javax.swing.SwingUtilities

/**
 * Installs lightweight Windows message hooks on a JFrame to capture system shutdown events and
 * route them into the launcher's normal graceful-quit flow.
 *
 * Specifically handles:
 * - WM_QUERYENDSESSION: signal that a logoff/shutdown is requested → start quit and return TRUE
 * - WM_ENDSESSION: confirms session end (wParam != 0) → start quit
 * - WM_CLOSE: user/system close request → start quit
 *
 * Uses JNA to subclass the window procedure and forwards all other messages to the original proc.
 * If anything fails (non-Windows, missing handle, API change), this is a no‑op.
 */
object WindowsMessageHooks {
  private const val CLIENT_PROP_KEY = "crypta.win.wndprocHook"

  fun install(frame: JFrame, onQuit: () -> Unit) {
    // Only applicable to Windows
    val os = System.getProperty("os.name").lowercase()
    if (!os.contains("win")) return

    // Ensure we run on the UI thread after the native peer is created
    val task = Runnable {
      try {
        // Avoid duplicate installation
        if (frame.rootPane.getClientProperty(CLIENT_PROP_KEY) != null) return@Runnable

        val hwnd = getHwnd(frame) ?: return@Runnable
        val hook = WndProcHook(hwnd, onQuit)
        frame.rootPane.putClientProperty(CLIENT_PROP_KEY, hook)
      } catch (_: Throwable) {}
    }
    if (SwingUtilities.isEventDispatchThread()) task.run() else SwingUtilities.invokeLater(task)
  }

  private fun getHwnd(frame: JFrame): HWND? =
    try {
      // WindowUtils is provided by jna-platform; returns an HWND for the Java Window
      WindowUtils.getWindowHandle(frame)
    } catch (_: Throwable) {
      null
    }

  /** Window procedure hook forwarding unhandled messages to the original WNDPROC. */
  private class WndProcHook(
    private val hWnd: HWND,
    private val onQuit: () -> Unit,
  ) : WinUser.WindowProc {
    private val prevWndProc: Pointer
    @Volatile private var invoked = false

    init {
      // Subclass the window procedure, remembering the previous one for forwarding
      val fnPtr: Pointer = CallbackReference.getFunctionPointer(this)
      prevWndProc = U32EX.SetWindowLongPtr(hWnd, WinUser.GWLP_WNDPROC, fnPtr)
    }

    override fun callback(h: HWND?, uMsg: Int, wParam: WPARAM?, lParam: LPARAM?): LRESULT {
      when (uMsg) {
        WinUser.WM_QUERYENDSESSION -> {
          // Begin graceful quit but allow shutdown to continue
          triggerQuitOnce()
          return LRESULT(1) // TRUE
        }
        WinUser.WM_ENDSESSION -> {
          if ((wParam?.toInt() ?: 0) != 0) triggerQuitOnce()
        }
        WinUser.WM_CLOSE -> {
          triggerQuitOnce()
        }
      }
      // Forward to the previous window procedure for normal processing
      return U32EX.CallWindowProc(prevWndProc, h, uMsg, wParam, lParam)
    }

    private fun triggerQuitOnce() {
      if (invoked) return
      invoked = true
      try {
        SwingUtilities.invokeLater { onQuit.invoke() }
      } catch (_: Throwable) {}
    }
  }
}

// Local narrow interface to avoid signature differences across JNA versions.
private interface User32Ex : com.sun.jna.win32.StdCallLibrary {
  fun SetWindowLongPtr(hWnd: HWND, nIndex: Int, dwNewLong: Pointer): Pointer
  fun CallWindowProc(
    lpPrevWndFunc: Pointer,
    hWnd: HWND?,
    uMsg: Int,
    wParam: WPARAM?,
    lParam: LPARAM?,
  ): LRESULT
}

private val U32EX: User32Ex =
  Native.load("user32", User32Ex::class.java, W32APIOptions.DEFAULT_OPTIONS)
