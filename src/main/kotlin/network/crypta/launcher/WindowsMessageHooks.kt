package network.crypta.launcher

import com.sun.jna.CallbackReference
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.WinDef.*
import com.sun.jna.platform.win32.WinUser
import com.sun.jna.win32.W32APIOptions
import javax.swing.JFrame
import javax.swing.SwingUtilities
import network.crypta.fs.AppEnv

/**
 * Installs lightweight Windows message hooks on a JFrame to capture system shutdown events and
 * route them into the launcher's normal graceful-quit flow.
 *
 * Specifically handles:
 * - WM_QUERYENDSESSION: signal that a logoff/shutdown is requested → start quit and return TRUE
 * - WM_ENDSESSION: confirms the session end (wParam != 0) → start quit
 * - WM_CLOSE: user/system close request → start quit
 *
 * Uses JNA to subclass the window procedure and forwards all other messages to the original proc.
 * If anything fails (non-Windows, missing handle, API change), this is a no‑op.
 */
object WindowsMessageHooks {
  /**
   * Windows message constants not exposed by jna-platform 5.17. Values match WinUser.h:
   * WM_QUERYENDSESSION (0x0011), WM_ENDSESSION (0x0016).
   */
  private const val WM_QUERYENDSESSION = 0x0011
  private const val WM_ENDSESSION = 0x0016
  private const val CLIENT_PROP_KEY = "crypta.win.wndprocHook"

  fun install(frame: JFrame, onQuit: () -> Unit) {
    // Only applicable to Windows
    if (!AppEnv().isWindows()) return

    // Ensure we run on the UI thread after the native peer is created
    val task = Runnable {
      try {
        // Avoid duplicate installation
        if (frame.rootPane.getClientProperty(CLIENT_PROP_KEY) != null) return@Runnable

        val hwnd = getHwnd(frame) ?: return@Runnable
        val hook = WndProcHook(hwnd, onQuit)
        frame.rootPane.putClientProperty(CLIENT_PROP_KEY, hook)
      } catch (t: Throwable) {
        logDebug("Failed to install Windows message hook", t)
      }
    }
    if (SwingUtilities.isEventDispatchThread()) task.run() else SwingUtilities.invokeLater(task)
  }

  private fun getHwnd(frame: JFrame): HWND? =
    try {
      // JNA 5.17 no longer exposes WindowUtils.getWindowHandle(Window).
      // Use Native.getWindowPointer(Window) and wrap it as HWND.
      val p: Pointer = Native.getWindowPointer(frame)
      if (p == Pointer.NULL) null else HWND(p)
    } catch (t: Throwable) {
      logDebug("Failed to resolve HWND from frame", t)
      null
    }

  /** Window procedure hook forwarding unhandled messages to the original WNDPROC. */
  private class WndProcHook(hWnd: HWND, private val onQuit: () -> Unit) : WinUser.WindowProc {
    private val prevWndProc: Pointer

    @Volatile private var invoked = false

    init {
      // Subclass the window procedure, remembering the previous one for forwarding
      val fnPtr: Pointer = CallbackReference.getFunctionPointer(this)
      // JNA does not expose GWLP_WNDPROC, but GWL_WNDPROC works for SetWindowLongPtr index
      prevWndProc = U32EX.SetWindowLongPtr(hWnd, WinUser.GWL_WNDPROC, fnPtr)
    }

    override fun callback(h: HWND?, uMsg: Int, wParam: WPARAM?, lParam: LPARAM?): LRESULT =
      when (uMsg) {
        WM_QUERYENDSESSION -> {
          // Begin graceful quit but allow shutdown to continue
          triggerQuitOnce()
          LRESULT(1) // TRUE
        }

        WM_ENDSESSION -> {
          if ((wParam?.toInt() ?: 0) != 0) triggerQuitOnce()
          U32EX.CallWindowProc(prevWndProc, h, uMsg, wParam, lParam)
        }

        WinUser.WM_CLOSE -> {
          triggerQuitOnce()
          U32EX.CallWindowProc(prevWndProc, h, uMsg, wParam, lParam)
        }

        // Forward all other messages for normal processing.
        else -> {
          U32EX.CallWindowProc(prevWndProc, h, uMsg, wParam, lParam)
        }
      }

    private fun triggerQuitOnce() {
      if (invoked) return
      invoked = true
      try {
        SwingUtilities.invokeLater { onQuit.invoke() }
      } catch (t: Throwable) {
        logDebug("Failed to post quit request from Windows hook", t)
      }
    }
  }
}

// Local narrow interface to avoid signature differences across JNA versions.
@Suppress("FunctionName")
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
