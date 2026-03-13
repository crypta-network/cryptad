package network.crypta.launcher;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import network.crypta.fs.AppEnv;

/**
 * Lightweight Windows close hook.
 *
 * <p>The previous Kotlin implementation subclassed native WNDPROC. The Java migration keeps a safe
 * fallback that routes close events into the launcher's graceful-quit flow.
 */
public final class WindowsMessageHooks {
  private WindowsMessageHooks() {}

  public static void install(JFrame frame, Runnable onQuit) {
    if (!new AppEnv().isWindows() || frame == null || onQuit == null) {
      return;
    }

    Runnable task =
        () ->
            frame.addWindowListener(
                new WindowAdapter() {
                  private volatile boolean invoked;

                  @Override
                  public void windowClosing(WindowEvent e) {
                    if (invoked) {
                      return;
                    }
                    invoked = true;
                    SwingUtilities.invokeLater(onQuit);
                  }
                });

    if (SwingUtilities.isEventDispatchThread()) {
      task.run();
    } else {
      SwingUtilities.invokeLater(task);
    }
  }
}
