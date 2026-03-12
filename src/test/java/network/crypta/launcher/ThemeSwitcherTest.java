package network.crypta.launcher;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.themes.FlatMacLightLaf;
import com.jthemedetecor.OsThemeDetector;
import java.util.function.Consumer;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.LookAndFeel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked"})
class ThemeSwitcherTest {
  private static final String APPLE_APPEARANCE_KEY = "apple.awt.application.appearance";
  private static final String SWING_DEFAULT_LAF_KEY = "swing.defaultlaf";

  @AfterEach
  void tearDown() {
    ThemeSwitcher.shutdown();
  }

  @Test
  void install_whenNonMacDark_thenRegistersListenerAndSwitchesOnChange() {
    String priorApple = System.getProperty(APPLE_APPEARANCE_KEY);
    String priorDefault = System.getProperty(SWING_DEFAULT_LAF_KEY);

    OsThemeDetector detector = mock(OsThemeDetector.class);
    when(detector.isDark()).thenReturn(true);

    try (MockedStatic<FlatpakAwareOsThemeDetector> detectorFactory =
            mockStatic(FlatpakAwareOsThemeDetector.class);
        var _ =
            mockConstruction(
                AppEnv.class,
                (mock, _) -> {
                  when(mock.isMac()).thenReturn(false);
                  when(mock.isLinux()).thenReturn(false);
                });
        MockedStatic<SwingUtilities> swingMock = mockStatic(SwingUtilities.class);
        MockedStatic<FlatLaf> flatLafMock = mockStatic(FlatLaf.class);
        MockedStatic<UIManager> uiManagerMock = mockStatic(UIManager.class)) {

      detectorFactory.when(FlatpakAwareOsThemeDetector::getDetector).thenReturn(detector);
      swingMock.when(SwingUtilities::isEventDispatchThread).thenReturn(false);
      swingMock
          .when(() -> SwingUtilities.invokeAndWait(any(Runnable.class)))
          .thenAnswer(
              invocation -> {
                Runnable runnable = invocation.getArgument(0);
                runnable.run();
                return null;
              });
      swingMock
          .when(() -> SwingUtilities.invokeLater(any(Runnable.class)))
          .thenAnswer(
              invocation -> {
                Runnable runnable = invocation.getArgument(0);
                runnable.run();
                return null;
              });
      uiManagerMock
          .when(() -> UIManager.setLookAndFeel(any(LookAndFeel.class)))
          .thenAnswer(_ -> null);
      uiManagerMock.when(() -> UIManager.put(anyString(), any())).thenAnswer(_ -> null);

      ArgumentCaptor<Consumer<Boolean>> listenerCaptor = ArgumentCaptor.forClass(Consumer.class);

      ThemeSwitcher.install();

      verify(detector).registerListener(listenerCaptor.capture());
      Consumer<Boolean> listener = listenerCaptor.getValue();
      assertNotNull(listener);

      ArgumentCaptor<LookAndFeel> lookAndFeelCaptor = ArgumentCaptor.forClass(LookAndFeel.class);
      listener.accept(false);

      uiManagerMock.verify(() -> UIManager.setLookAndFeel(lookAndFeelCaptor.capture()), times(2));
      assertInstanceOf(FlatDarkLaf.class, lookAndFeelCaptor.getAllValues().get(0));
      assertInstanceOf(FlatLightLaf.class, lookAndFeelCaptor.getAllValues().get(1));

      boolean expectedNativeDeco =
          System.getenv("FLATPAK_ID") == null || System.getenv("FLATPAK_ID").isEmpty();
      flatLafMock.verify(() -> FlatLaf.setUseNativeWindowDecorations(expectedNativeDeco), times(2));
      flatLafMock.verify(() -> FlatLaf.setup(any(LookAndFeel.class)), times(2));
      flatLafMock.verify(FlatLaf::updateUI, times(1));
    } finally {
      restoreProperty(APPLE_APPEARANCE_KEY, priorApple);
      restoreProperty(SWING_DEFAULT_LAF_KEY, priorDefault);
    }
  }

  @Test
  void install_whenMacLight_thenSetsDefaultFontAndDisablesNativeDecorations() {
    String priorApple = System.getProperty(APPLE_APPEARANCE_KEY);
    String priorDefault = System.getProperty(SWING_DEFAULT_LAF_KEY);

    OsThemeDetector detector = mock(OsThemeDetector.class);
    when(detector.isDark()).thenReturn(false);

    try (MockedStatic<FlatpakAwareOsThemeDetector> detectorFactory =
            mockStatic(FlatpakAwareOsThemeDetector.class);
        var _ =
            mockConstruction(
                AppEnv.class,
                (mock, _) -> {
                  when(mock.isMac()).thenReturn(true);
                  when(mock.isLinux()).thenReturn(false);
                });
        MockedStatic<SwingUtilities> swingMock = mockStatic(SwingUtilities.class);
        MockedStatic<FlatLaf> flatLafMock = mockStatic(FlatLaf.class);
        MockedStatic<UIManager> uiManagerMock = mockStatic(UIManager.class)) {

      detectorFactory.when(FlatpakAwareOsThemeDetector::getDetector).thenReturn(detector);
      swingMock.when(SwingUtilities::isEventDispatchThread).thenReturn(true);
      swingMock
          .when(() -> SwingUtilities.invokeLater(any(Runnable.class)))
          .thenAnswer(
              invocation -> {
                Runnable runnable = invocation.getArgument(0);
                runnable.run();
                return null;
              });
      uiManagerMock
          .when(() -> UIManager.setLookAndFeel(any(LookAndFeel.class)))
          .thenAnswer(_ -> null);
      uiManagerMock.when(() -> UIManager.put(anyString(), any())).thenAnswer(_ -> null);

      ThemeSwitcher.install();

      uiManagerMock.verify(
          () ->
              UIManager.put(
                  org.mockito.ArgumentMatchers.eq("defaultFont"), any(FontUIResource.class)));
      flatLafMock.verify(() -> FlatLaf.setUseNativeWindowDecorations(false));

      ArgumentCaptor<LookAndFeel> lookAndFeelCaptor = ArgumentCaptor.forClass(LookAndFeel.class);
      uiManagerMock.verify(() -> UIManager.setLookAndFeel(lookAndFeelCaptor.capture()));
      assertInstanceOf(FlatMacLightLaf.class, lookAndFeelCaptor.getValue());
      assertEquals(FlatMacLightLaf.class.getName(), System.getProperty(SWING_DEFAULT_LAF_KEY));

      flatLafMock.verify(FlatLaf::updateUI, times(0));
    } finally {
      restoreProperty(APPLE_APPEARANCE_KEY, priorApple);
      restoreProperty(SWING_DEFAULT_LAF_KEY, priorDefault);
    }
  }

  @Test
  void install_whenLinux_thenEnablesClientDecorationsAndShutdownUnregistersListener()
      throws Exception {
    String priorApple = System.getProperty(APPLE_APPEARANCE_KEY);
    String priorDefault = System.getProperty(SWING_DEFAULT_LAF_KEY);

    OsThemeDetector detector =
        mock(OsThemeDetector.class, withSettings().extraInterfaces(AutoCloseable.class));
    AutoCloseable closeableDetector = (AutoCloseable) detector;
    when(detector.isDark()).thenReturn(false);

    try (MockedStatic<FlatpakAwareOsThemeDetector> detectorFactory =
            mockStatic(FlatpakAwareOsThemeDetector.class);
        var _ =
            mockConstruction(
                AppEnv.class,
                (mock, _) -> {
                  when(mock.isMac()).thenReturn(false);
                  when(mock.isLinux()).thenReturn(true);
                });
        MockedStatic<SwingUtilities> swingMock = mockStatic(SwingUtilities.class);
        MockedStatic<FlatLaf> flatLafMock = mockStatic(FlatLaf.class);
        MockedStatic<UIManager> uiManagerMock = mockStatic(UIManager.class);
        MockedStatic<JFrame> frameMock = mockStatic(JFrame.class);
        MockedStatic<JDialog> dialogMock = mockStatic(JDialog.class)) {

      detectorFactory.when(FlatpakAwareOsThemeDetector::getDetector).thenReturn(detector);
      swingMock.when(SwingUtilities::isEventDispatchThread).thenReturn(false);
      swingMock
          .when(() -> SwingUtilities.invokeAndWait(any(Runnable.class)))
          .thenAnswer(
              invocation -> {
                Runnable runnable = invocation.getArgument(0);
                runnable.run();
                return null;
              });
      swingMock
          .when(() -> SwingUtilities.invokeLater(any(Runnable.class)))
          .thenAnswer(
              invocation -> {
                Runnable runnable = invocation.getArgument(0);
                runnable.run();
                return null;
              });
      uiManagerMock
          .when(() -> UIManager.setLookAndFeel(any(LookAndFeel.class)))
          .thenAnswer(_ -> null);
      uiManagerMock.when(() -> UIManager.put(anyString(), any())).thenAnswer(_ -> null);

      ArgumentCaptor<Consumer<Boolean>> listenerCaptor = ArgumentCaptor.forClass(Consumer.class);

      ThemeSwitcher.install();

      frameMock.verify(() -> JFrame.setDefaultLookAndFeelDecorated(true));
      dialogMock.verify(() -> JDialog.setDefaultLookAndFeelDecorated(true));
      verify(detector).registerListener(listenerCaptor.capture());

      Consumer<Boolean> listener = listenerCaptor.getValue();
      ThemeSwitcher.shutdown();

      verify(detector).removeListener(listener);
      verify(closeableDetector).close();
      flatLafMock.verify(() -> FlatLaf.setup(any(LookAndFeel.class)));
    } finally {
      restoreProperty(APPLE_APPEARANCE_KEY, priorApple);
      restoreProperty(SWING_DEFAULT_LAF_KEY, priorDefault);
    }
  }

  private static void restoreProperty(String key, String value) {
    if (value == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, value);
    }
  }
}
