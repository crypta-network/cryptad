package network.crypta.launcher

import com.formdev.flatlaf.FlatDarkLaf
import com.formdev.flatlaf.FlatLaf
import com.formdev.flatlaf.FlatLightLaf
import com.formdev.flatlaf.themes.FlatMacLightLaf
import com.jthemedetecor.OsThemeDetector
import com.jthemedetecor.PortalThemeDetector
import java.util.function.Consumer
import javax.swing.JDialog
import javax.swing.JFrame
import javax.swing.SwingUtilities
import javax.swing.UIManager
import javax.swing.plaf.FontUIResource
import network.crypta.fs.AppEnv
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.mockito.ArgumentCaptor
import org.mockito.MockedConstruction
import org.mockito.MockedStatic
import org.mockito.Mockito
import org.mockito.junit.jupiter.MockitoExtension

@ExtendWith(MockitoExtension::class)
@SuppressWarnings("java:S100")
@Suppress("kotlin:S100")
internal class ThemeSwitcherTest {
  companion object {
    private const val APPLE_APPEARANCE_KEY = "apple.awt.application.appearance"
    private const val SWING_DEFAULT_LAF_KEY = "swing.defaultlaf"
  }

  @AfterEach
  fun tearDown() {
    ThemeSwitcher.shutdown()
  }

  @Test
  fun install_whenNonMacDark_thenRegistersListenerAndSwitchesOnChange() {
    val priorApple = System.getProperty(APPLE_APPEARANCE_KEY)
    val priorDefaultLaf = System.getProperty(SWING_DEFAULT_LAF_KEY)

    val detector = Mockito.mock(OsThemeDetector::class.java)
    Mockito.`when`(detector.isDark).thenReturn(true)

    val osDetectorMock = Mockito.mockStatic(OsThemeDetector::class.java)
    val appEnvConstruction =
      Mockito.mockConstruction(AppEnv::class.java) { mock, _ ->
        Mockito.`when`(mock.isMac()).thenReturn(false)
        Mockito.`when`(mock.isLinux()).thenReturn(false)
      }
    val swingMock = Mockito.mockStatic(SwingUtilities::class.java)
    val flatLafMock = Mockito.mockStatic(FlatLaf::class.java)
    val uiManagerMock = Mockito.mockStatic(UIManager::class.java)

    osDetectorMock.`when`<OsThemeDetector> { OsThemeDetector.getDetector() }.thenReturn(detector)
    swingMock.`when`<Boolean> { SwingUtilities.isEventDispatchThread() }.thenReturn(false)
    swingMock
      .`when`<Unit> { SwingUtilities.invokeAndWait(Mockito.any(Runnable::class.java)) }
      .thenAnswer { invocation ->
        val runnable = invocation.arguments[0] as Runnable
        runnable.run()
        null
      }
    swingMock
      .`when`<Unit> { SwingUtilities.invokeLater(Mockito.any(Runnable::class.java)) }
      .thenAnswer { invocation ->
        val runnable = invocation.arguments[0] as Runnable
        runnable.run()
        null
      }
    uiManagerMock
      .`when`<Unit> { UIManager.setLookAndFeel(Mockito.any(javax.swing.LookAndFeel::class.java)) }
      .thenAnswer { null }
    uiManagerMock
      .`when`<Any> { UIManager.put(Mockito.anyString(), Mockito.any(Any::class.java)) }
      .thenAnswer { null }

    try {
      // Arrange
      @Suppress("UNCHECKED_CAST")
      val listenerCaptor: ArgumentCaptor<Consumer<Boolean>> =
        ArgumentCaptor.forClass(Consumer::class.java) as ArgumentCaptor<Consumer<Boolean>>

      // Act
      ThemeSwitcher.install()

      // Assert
      Mockito.verify(detector).registerListener(listenerCaptor.capture())
      val listener = listenerCaptor.value
      assertNotNull(listener)

      val lookAndFeelCaptor = ArgumentCaptor.forClass(javax.swing.LookAndFeel::class.java)

      // Act
      listener.accept(false)

      // Assert
      uiManagerMock.verify(
        { UIManager.setLookAndFeel(lookAndFeelCaptor.capture()) },
        Mockito.times(2),
      )
      assertTrue(lookAndFeelCaptor.allValues.first() is FlatDarkLaf)
      assertTrue(lookAndFeelCaptor.allValues.last() is FlatLightLaf)

      val expectedNativeDeco = System.getenv("FLATPAK_ID").isNullOrEmpty()
      flatLafMock.verify(
        { FlatLaf.setUseNativeWindowDecorations(expectedNativeDeco) },
        Mockito.times(2),
      )
      flatLafMock.verify(
        { FlatLaf.setup(Mockito.any(javax.swing.LookAndFeel::class.java)) },
        Mockito.times(2),
      )
      flatLafMock.verify({ FlatLaf.updateUI() }, Mockito.times(1))
      uiManagerMock.verify(
        { UIManager.put(Mockito.anyString(), Mockito.any(Any::class.java)) },
        Mockito.never(),
      )
    } finally {
      osDetectorMock.close()
      appEnvConstruction.close()
      swingMock.close()
      flatLafMock.close()
      uiManagerMock.close()
      if (priorApple == null) {
        System.clearProperty(APPLE_APPEARANCE_KEY)
      } else {
        System.setProperty(APPLE_APPEARANCE_KEY, priorApple)
      }
      if (priorDefaultLaf == null) {
        System.clearProperty(SWING_DEFAULT_LAF_KEY)
      } else {
        System.setProperty(SWING_DEFAULT_LAF_KEY, priorDefaultLaf)
      }
    }
  }

  @Test
  fun install_whenMacLight_thenSetsDefaultFontAndDisablesNativeDecorations() {
    val priorApple = System.getProperty(APPLE_APPEARANCE_KEY)
    val priorDefaultLaf = System.getProperty(SWING_DEFAULT_LAF_KEY)

    val detector = Mockito.mock(OsThemeDetector::class.java)
    Mockito.`when`(detector.isDark).thenReturn(false)

    val osDetectorMock = Mockito.mockStatic(OsThemeDetector::class.java)
    val appEnvConstruction =
      Mockito.mockConstruction(AppEnv::class.java) { mock, _ ->
        Mockito.`when`(mock.isMac()).thenReturn(true)
        Mockito.`when`(mock.isLinux()).thenReturn(false)
      }
    val swingMock = Mockito.mockStatic(SwingUtilities::class.java)
    val flatLafMock = Mockito.mockStatic(FlatLaf::class.java)
    val uiManagerMock = Mockito.mockStatic(UIManager::class.java)

    osDetectorMock.`when`<OsThemeDetector> { OsThemeDetector.getDetector() }.thenReturn(detector)
    swingMock.`when`<Boolean> { SwingUtilities.isEventDispatchThread() }.thenReturn(true)
    swingMock
      .`when`<Unit> { SwingUtilities.invokeLater(Mockito.any(Runnable::class.java)) }
      .thenAnswer { invocation ->
        val runnable = invocation.arguments[0] as Runnable
        runnable.run()
        null
      }
    uiManagerMock
      .`when`<Unit> { UIManager.setLookAndFeel(Mockito.any(javax.swing.LookAndFeel::class.java)) }
      .thenAnswer { null }
    uiManagerMock
      .`when`<Any> { UIManager.put(Mockito.anyString(), Mockito.any(Any::class.java)) }
      .thenAnswer { null }

    try {
      // Act
      ThemeSwitcher.install()

      // Assert
      uiManagerMock.verify {
        UIManager.put(Mockito.eq("defaultFont"), Mockito.any(FontUIResource::class.java))
      }
      flatLafMock.verify { FlatLaf.setUseNativeWindowDecorations(false) }
      val lookAndFeelCaptor = ArgumentCaptor.forClass(javax.swing.LookAndFeel::class.java)
      uiManagerMock.verify { UIManager.setLookAndFeel(lookAndFeelCaptor.capture()) }
      assertTrue(lookAndFeelCaptor.value is FlatMacLightLaf)
      assertEquals(FlatMacLightLaf::class.java.name, System.getProperty(SWING_DEFAULT_LAF_KEY))
      flatLafMock.verify({ FlatLaf.updateUI() }, Mockito.never())
    } finally {
      osDetectorMock.close()
      appEnvConstruction.close()
      swingMock.close()
      flatLafMock.close()
      uiManagerMock.close()
      if (priorApple == null) {
        System.clearProperty(APPLE_APPEARANCE_KEY)
      } else {
        System.setProperty(APPLE_APPEARANCE_KEY, priorApple)
      }
      if (priorDefaultLaf == null) {
        System.clearProperty(SWING_DEFAULT_LAF_KEY)
      } else {
        System.setProperty(SWING_DEFAULT_LAF_KEY, priorDefaultLaf)
      }
    }
  }

  @Test
  fun install_whenLinux_thenEnablesClientDecorationsAndShutdownUnregistersListener() {
    val priorApple = System.getProperty(APPLE_APPEARANCE_KEY)
    val priorDefaultLaf = System.getProperty(SWING_DEFAULT_LAF_KEY)

    val appEnvConstruction: MockedConstruction<AppEnv> =
      Mockito.mockConstruction(AppEnv::class.java) { mock, _ ->
        Mockito.`when`(mock.isMac()).thenReturn(false)
        Mockito.`when`(mock.isLinux()).thenReturn(true)
      }
    val portalConstruction: MockedConstruction<PortalThemeDetector> =
      Mockito.mockConstruction(PortalThemeDetector::class.java) { mock, _ ->
        Mockito.`when`(mock.isDark).thenReturn(false)
      }
    val swingMock: MockedStatic<SwingUtilities> = Mockito.mockStatic(SwingUtilities::class.java)
    val flatLafMock: MockedStatic<FlatLaf> = Mockito.mockStatic(FlatLaf::class.java)
    val uiManagerMock: MockedStatic<UIManager> = Mockito.mockStatic(UIManager::class.java)
    val jFrameMock: MockedStatic<JFrame> = Mockito.mockStatic(JFrame::class.java)
    val jDialogMock: MockedStatic<JDialog> = Mockito.mockStatic(JDialog::class.java)

    swingMock.`when`<Boolean> { SwingUtilities.isEventDispatchThread() }.thenReturn(false)
    swingMock
      .`when`<Unit> { SwingUtilities.invokeAndWait(Mockito.any(Runnable::class.java)) }
      .thenAnswer { invocation ->
        val runnable = invocation.arguments[0] as Runnable
        runnable.run()
        null
      }
    swingMock
      .`when`<Unit> { SwingUtilities.invokeLater(Mockito.any(Runnable::class.java)) }
      .thenAnswer { invocation ->
        val runnable = invocation.arguments[0] as Runnable
        runnable.run()
        null
      }
    uiManagerMock
      .`when`<Unit> { UIManager.setLookAndFeel(Mockito.any(javax.swing.LookAndFeel::class.java)) }
      .thenAnswer { null }
    uiManagerMock
      .`when`<Any> { UIManager.put(Mockito.anyString(), Mockito.any(Any::class.java)) }
      .thenAnswer { null }
    jFrameMock.`when`<Unit> { JFrame.setDefaultLookAndFeelDecorated(true) }.thenAnswer { null }
    jDialogMock.`when`<Unit> { JDialog.setDefaultLookAndFeelDecorated(true) }.thenAnswer { null }

    try {
      // Act
      ThemeSwitcher.install()

      // Assert
      jFrameMock.verify { JFrame.setDefaultLookAndFeelDecorated(true) }
      jDialogMock.verify { JDialog.setDefaultLookAndFeelDecorated(true) }

      assertTrue(portalConstruction.constructed().isNotEmpty())
      val detector = portalConstruction.constructed().first()
      val listenerField = ThemeSwitcher::class.java.getDeclaredField("listener")
      listenerField.isAccessible = true
      @Suppress("UNCHECKED_CAST", "kotlin:S6518")
      val listener = requireNotNull(listenerField.get(null) as Consumer<Boolean>?)
      Mockito.verify(detector).registerListener(listener)

      ThemeSwitcher.shutdown()

      Mockito.verify(detector).removeListener(listener)
      flatLafMock.verify { FlatLaf.setup(Mockito.any(javax.swing.LookAndFeel::class.java)) }
    } finally {
      appEnvConstruction.close()
      portalConstruction.close()
      swingMock.close()
      flatLafMock.close()
      uiManagerMock.close()
      jFrameMock.close()
      jDialogMock.close()
      if (priorApple == null) {
        System.clearProperty(APPLE_APPEARANCE_KEY)
      } else {
        System.setProperty(APPLE_APPEARANCE_KEY, priorApple)
      }
      if (priorDefaultLaf == null) {
        System.clearProperty(SWING_DEFAULT_LAF_KEY)
      } else {
        System.setProperty(SWING_DEFAULT_LAF_KEY, priorDefaultLaf)
      }
    }
  }
}
