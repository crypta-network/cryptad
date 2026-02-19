package network.crypta.launcher;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.KeyboardFocusManager;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import network.crypta.fs.AppEnv;

import static network.crypta.launcher.LauncherLog.logDebug;

/** Java launcher entrypoint. */
public final class Launcher {
  private static final String APP_NAME = "Crypta Launcher";
  private static final AtomicReference<CryptaLauncher> INSTANCE = new AtomicReference<>();

  private Launcher() {}

  static void main() {
    installLookAndFeel();
    SwingUtilities.invokeLater(
        () -> {
          CryptaLauncher launcher = new CryptaLauncher();
          if (!INSTANCE.compareAndSet(null, launcher)) {
            CryptaLauncher existing = INSTANCE.get();
            if (existing != null) {
              existing.setVisible(true);
              existing.toFront();
              existing.requestFocus();
            }
            return;
          }
          launcher.setVisible(true);
          launcher.startAutomatically();
        });
  }

  private static void installLookAndFeel() {
    try {
      ThemeSwitcher.install();
    } catch (Exception e) {
      logDebug("ThemeSwitcher.install() failed", e);
      try {
        javax.swing.UIManager.setLookAndFeel(javax.swing.UIManager.getSystemLookAndFeelClassName());
      } catch (Exception _) {
        // Keep the default Swing look and feel.
      }
    }
  }

  private static final class CryptaLauncher extends JFrame {
    private final transient LauncherController controller;
    private final JButton startStopBtn;
    private final JButton launchBtn;
    private final JButton quitBtn;
    private final JTextArea logArea;

    private CryptaLauncher() {
      super(APP_NAME);

      controller = new LauncherController();
      startStopBtn = new JButton("Start");
      launchBtn = new JButton("Launch in Browser");
      quitBtn = new JButton("Quit");
      logArea = new JTextArea();

      setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
      setMinimumSize(new Dimension(450, 300));
      setLayout(new BorderLayout());

      JPanel top = new JPanel();
      top.add(startStopBtn);
      top.add(launchBtn);
      top.add(quitBtn);
      add(top, BorderLayout.NORTH);

      logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
      logArea.setEditable(false);
      logArea.setLineWrap(false);
      logArea.setWrapStyleWord(false);
      add(new JScrollPane(logArea), BorderLayout.CENTER);

      add(
          new JLabel("Left/Right focus buttons, Enter click, s start/stop, q quit, ↑/↓ scroll log"),
          BorderLayout.SOUTH);

      startStopBtn.addActionListener(
          _ -> {
            AppState state = controller.getState();
            if (state.isStoppingOrShuttingDown()) {
              return;
            }
            if (state.isRunning()) {
              controller.stop();
            } else {
              controller.start();
            }
          });
      launchBtn.addActionListener(_ -> controller.launchBrowser());
      quitBtn.addActionListener(_ -> quitApp());

      controller.addLogListener(this::appendLogLine);
      controller.addStateListener(this::renderState);

      addWindowListener(
          new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
              if (new AppEnv().isMac()) {
                setVisible(false);
              } else {
                quitApp();
              }
            }
          });

      KeyboardFocusManager.getCurrentKeyboardFocusManager()
          .addKeyEventDispatcher(
              event -> {
                if (event.getID() != KeyEvent.KEY_PRESSED) {
                  return false;
                }
                return handleShortcut(event);
              });

      try {
        var icon = LauncherUtils.loadAppIconImage();
        if (icon != null) {
          setIconImage(icon);
        }
      } catch (Exception _) {
        // Optional visual enhancement.
      }

      pack();
      setLocationRelativeTo(null);
      WindowsMessageHooks.install(this, this::quitApp);
    }

    private boolean handleShortcut(KeyEvent event) {
      switch (event.getKeyCode()) {
        case KeyEvent.VK_S -> {
          if (controller.getState().isRunning()) {
            controller.stop();
          } else {
            controller.start();
          }
          event.consume();
          return true;
        }
        case KeyEvent.VK_Q -> {
          quitApp();
          event.consume();
          return true;
        }
        case KeyEvent.VK_LEFT -> {
          focusCycle(-1);
          event.consume();
          return true;
        }
        case KeyEvent.VK_RIGHT -> {
          focusCycle(1);
          event.consume();
          return true;
        }
        case KeyEvent.VK_UP -> {
          scrollBy(-1);
          event.consume();
          return true;
        }
        case KeyEvent.VK_DOWN -> {
          scrollBy(1);
          event.consume();
          return true;
        }
        default -> {
          return false;
        }
      }
    }

    private void focusCycle(int direction) {
      JButton[] order = {startStopBtn, launchBtn, quitBtn};
      int current = -1;
      for (int i = 0; i < order.length; i++) {
        if (order[i].isFocusOwner()) {
          current = i;
          break;
        }
      }
      int next = current < 0 ? 0 : Math.floorMod(current + direction, order.length);
      order[next].requestFocusInWindow();
    }

    private void scrollBy(int direction) {
      JScrollPane pane = (JScrollPane) logArea.getParent().getParent();
      int row = logArea.getFontMetrics(logArea.getFont()).getHeight();
      int delta = row * direction;
      int upper =
          Math.max(
              0,
              pane.getVerticalScrollBar().getMaximum()
                  - pane.getVerticalScrollBar().getVisibleAmount());
      long rawTarget = (long) pane.getVerticalScrollBar().getValue() + delta;
      int next = (int) Math.clamp(rawTarget, 0L, upper);
      pane.getVerticalScrollBar().setValue(next);
    }

    private void appendLogLine(String line) {
      SwingUtilities.invokeLater(
          () -> {
            logArea.append(line);
            logArea.append("\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
          });
    }

    private void renderState(AppState state) {
      SwingUtilities.invokeLater(
          () -> {
            startStopBtn.setText(state.isRunning() ? "Stop" : "Start");
            startStopBtn.setEnabled(!state.isShuttingDown());
            launchBtn.setEnabled(
                state.isRunning() && state.knownPort() != null && !state.isShuttingDown());
            launchBtn.setToolTipText(
                state.knownPort() == null
                    ? "Open http://localhost:<port>/ in your browser"
                    : "Open http://localhost:" + state.knownPort() + "/ in your browser");
          });
    }

    private void quitApp() {
      startStopBtn.setEnabled(false);
      launchBtn.setEnabled(false);
      quitBtn.setEnabled(false);
      controller.shutdownAndWait();
      try {
        ThemeSwitcher.shutdown();
      } catch (Exception e) {
        logDebug("ThemeSwitcher.shutdown() failed", e);
      }
      dispose();
      INSTANCE.compareAndSet(this, null);
    }

    private void startAutomatically() {
      SwingUtilities.invokeLater(controller::start);
    }
  }
}
