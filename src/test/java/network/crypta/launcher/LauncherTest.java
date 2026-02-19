package network.crypta.launcher;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

@SuppressWarnings({"java:S100"})
class LauncherTest {

  @Test
  void main_whenThemeInstallSucceeds_schedulesLauncherOnEdt() {
    try (MockedStatic<ThemeSwitcher> themeSwitcher = mockStatic(ThemeSwitcher.class);
        MockedStatic<SwingUtilities> swingUtilities = mockStatic(SwingUtilities.class)) {

      swingUtilities
          .when(() -> SwingUtilities.invokeLater(any(Runnable.class)))
          .thenAnswer(_ -> null);

      assertDoesNotThrow(Launcher::main);

      themeSwitcher.verify(ThemeSwitcher::install, times(1));
      swingUtilities.verify(() -> SwingUtilities.invokeLater(any(Runnable.class)), times(1));
    }
  }

  @Test
  void main_whenThemeInstallFails_appliesSystemLookAndFeelAndSchedulesLauncher() {
    String systemLookAndFeel = "javax.swing.plaf.metal.MetalLookAndFeel";
    try (MockedStatic<ThemeSwitcher> themeSwitcher = mockStatic(ThemeSwitcher.class);
        MockedStatic<UIManager> uiManager = mockStatic(UIManager.class);
        MockedStatic<SwingUtilities> swingUtilities = mockStatic(SwingUtilities.class)) {

      themeSwitcher.when(ThemeSwitcher::install).thenThrow(new RuntimeException("boom"));
      uiManager.when(UIManager::getSystemLookAndFeelClassName).thenReturn(systemLookAndFeel);
      uiManager.when(() -> UIManager.setLookAndFeel(systemLookAndFeel)).thenAnswer(_ -> null);
      swingUtilities
          .when(() -> SwingUtilities.invokeLater(any(Runnable.class)))
          .thenAnswer(_ -> null);

      assertDoesNotThrow(Launcher::main);

      themeSwitcher.verify(ThemeSwitcher::install, times(1));
      uiManager.verify(UIManager::getSystemLookAndFeelClassName, times(1));
      uiManager.verify(() -> UIManager.setLookAndFeel(systemLookAndFeel), times(1));
      swingUtilities.verify(() -> SwingUtilities.invokeLater(any(Runnable.class)), times(1));
    }
  }

  @Test
  void main_whenThemeAndFallbackLookAndFeelFail_stillSchedulesLauncher() {
    String systemLookAndFeel = "javax.swing.plaf.metal.MetalLookAndFeel";
    try (MockedStatic<ThemeSwitcher> themeSwitcher = mockStatic(ThemeSwitcher.class);
        MockedStatic<UIManager> uiManager = mockStatic(UIManager.class);
        MockedStatic<SwingUtilities> swingUtilities = mockStatic(SwingUtilities.class)) {

      themeSwitcher.when(ThemeSwitcher::install).thenThrow(new RuntimeException("boom"));
      uiManager.when(UIManager::getSystemLookAndFeelClassName).thenReturn(systemLookAndFeel);
      uiManager
          .when(() -> UIManager.setLookAndFeel(systemLookAndFeel))
          .thenThrow(new RuntimeException("laf-fail"));
      swingUtilities
          .when(() -> SwingUtilities.invokeLater(any(Runnable.class)))
          .thenAnswer(_ -> null);

      assertDoesNotThrow(Launcher::main);

      themeSwitcher.verify(ThemeSwitcher::install, times(1));
      uiManager.verify(UIManager::getSystemLookAndFeelClassName, times(1));
      uiManager.verify(() -> UIManager.setLookAndFeel(systemLookAndFeel), times(1));
      swingUtilities.verify(() -> SwingUtilities.invokeLater(any(Runnable.class)), times(1));
    }
  }
}
