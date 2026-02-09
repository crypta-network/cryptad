package network.crypta.launcher

import java.awt.Desktop
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.intrinsics.COROUTINE_SUSPENDED
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import network.crypta.fs.AppEnv
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.io.TempDir
import org.mockito.Mockito
import org.mockito.Mockito.mock
import org.mockito.Mockito.mockStatic
import org.mockito.Mockito.timeout
import org.mockito.junit.jupiter.MockitoExtension

@Suppress("java:S100", "kotlin:S100")
@ExtendWith(MockitoExtension::class)
internal class LauncherControllerTest {
  @TempDir private lateinit var tempDir: Path

  private companion object {
    private const val TEST_PORT = 8888
  }

  @Test
  fun start_whenCryptadMissing_logsErrorAndDoesNotRun() {
    val scope = newScope()
    val controller = LauncherController(scope, Dispatchers.IO, tempDir)
    val logs = startLogCollector(scope, controller)

    try {
      controller.start()

      val line = awaitLog(logs.lines) { it.contains("Cannot find executable 'cryptad'") }
      assertTrue(line.contains("ERROR: Cannot find executable 'cryptad'"))
      assertFalse(controller.state.value.isRunning)
    } finally {
      scope.cancel()
    }
  }

  @Test
  fun start_whenScriptRuns_updatesStateAndReadsPort() {
    val scope = newScope()
    val controller = LauncherController(scope, Dispatchers.IO, tempDir)
    val logs = startLogCollector(scope, controller)
    val wrapperConf = writeWrapperConf(tempDir)
    writeCryptadScript(tempDir)
    setPrivateField(controller, "autoOpenedBrowser", true)

    try {
      controller.start()

      awaitState(controller) { it.isRunning }
      val stateWithPort = awaitState(controller) { it.knownPort == TEST_PORT }
      assertEquals(TEST_PORT, stateWithPort.knownPort)

      val stoppedState = awaitState(controller) { !it.isRunning && it.knownPort == TEST_PORT }
      assertFalse(stoppedState.isRunning)

      awaitLog(logs.lines) { it.contains("Starting FProxy on") }
      assertTrue(logs.lines.any { it.contains("Starting 'cryptad'") })
      assertTrue(logs.lines.any { it.contains("exec:") })
      assertTrue(logs.lines.any { it.contains("Starting FProxy on") })

      val confLines = Files.readAllLines(wrapperConf, StandardCharsets.UTF_8).toList()
      assertTrue(confLines.any { it.trim() == "wrapper.console.flush=TRUE" })
    } finally {
      scope.cancel()
    }
  }

  @Test
  fun stop_whenProcessNotAlive_clearsRunningState() {
    val scope = newScope()
    val controller = LauncherController(scope, Dispatchers.IO, tempDir)
    val process = mock(Process::class.java)
    Mockito.`when`(process.isAlive).thenReturn(false)
    setPrivateField(controller, "process", process)
    setState(controller, AppState(isRunning = true))

    try {
      controller.stop()

      val state = getPrivateState(controller)
      assertFalse(state.isRunning)
      assertFalse(state.isStopping)
    } finally {
      scope.cancel()
    }
  }

  @Test
  fun launchBrowser_whenDesktopSupported_invokesBrowse() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
    val controller = LauncherController(scope, Dispatchers.Unconfined, tempDir)
    val desktop = mock(Desktop::class.java)
    Mockito.`when`(desktop.isSupported(Desktop.Action.BROWSE)).thenReturn(true)
    setState(controller, AppState(knownPort = 1234))

    try {
      mockStatic(Desktop::class.java).use { desktopStatic ->
        desktopStatic.`when`<Boolean> { Desktop.isDesktopSupported() }.thenReturn(true)
        desktopStatic.`when`<Desktop> { Desktop.getDesktop() }.thenReturn(desktop)

        controller.launchBrowser()

        Mockito.verify(desktop, timeout(1_000)).browse(URI.create("http://localhost:1234/"))
      }
    } finally {
      scope.cancel()
    }
  }

  @Test
  fun shutdown_setsShuttingDownFlagAndIsIdempotent() {
    val scope = newScope()
    val controller = LauncherController(scope, Dispatchers.IO, tempDir)

    try {
      controller.shutdown()
      assertTrue(getPrivateState(controller).isShuttingDown)

      controller.shutdown()
      assertTrue(getPrivateState(controller).isShuttingDown)
    } finally {
      scope.cancel()
    }
  }

  @Test
  fun shutdownAndWait_whenNoProcess_setsShuttingDownFlag() {
    val scope = newScope()
    val controller = LauncherController(scope, Dispatchers.IO, tempDir)

    try {
      invokeShutdownAndWait(controller)

      assertTrue(getPrivateState(controller).isShuttingDown)
    } finally {
      scope.cancel()
    }
  }

  private fun newScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

  private fun startLogCollector(
    scope: CoroutineScope,
    controller: LauncherController,
  ): LogCollector {
    val lines = CopyOnWriteArrayList<String>()
    scope.launch { controller.logs.collect { line -> lines.add(line) } }
    return LogCollector(lines)
  }

  private fun awaitLog(lines: List<String>, predicate: (String) -> Boolean): String {
    val deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
    while (System.nanoTime() < deadlineNanos) {
      lines.firstOrNull(predicate)?.let {
        return it
      }
      Thread.sleep(10)
    }
    error("Timed out waiting for expected launcher log line")
  }

  private fun awaitState(
    controller: LauncherController,
    predicate: (AppState) -> Boolean,
  ): AppState {
    val deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
    while (System.nanoTime() < deadlineNanos) {
      val state = controller.state.value
      if (predicate(state)) return state
      Thread.sleep(10)
    }
    error("Timed out waiting for launcher state")
  }

  private fun invokeShutdownAndWait(controller: LauncherController) {
    val completionLatch = CountDownLatch(1)
    var failure: Throwable? = null
    val continuation =
      object : Continuation<Unit> {
        override val context: CoroutineContext = EmptyCoroutineContext

        override fun resumeWith(result: Result<Unit>) {
          failure = result.exceptionOrNull()
          completionLatch.countDown()
        }
      }

    val method = controller.javaClass.getDeclaredMethod("shutdownAndWait", Continuation::class.java)
    method.isAccessible = true
    val result =
      try {
        method.invoke(controller, continuation)
      } catch (e: java.lang.reflect.InvocationTargetException) {
        throw (e.targetException ?: e)
      }
    if (result !== COROUTINE_SUSPENDED) {
      completionLatch.countDown()
    }
    if (!completionLatch.await(5, TimeUnit.SECONDS)) {
      error("Timed out waiting for shutdownAndWait completion")
    }
    failure?.let { throw AssertionError("shutdownAndWait failed", it) }
  }

  private fun writeCryptadScript(baseDir: Path): Path {
    val binDir = baseDir.resolve("bin")
    Files.createDirectories(binDir)
    val isWindows = AppEnv().isWindows()
    val script = if (isWindows) binDir.resolve("cryptad.bat") else binDir.resolve("cryptad")
    val content =
      if (isWindows) {
        """
                @echo off
                echo Starting FProxy on 127.0.0.1:$TEST_PORT
                echo READY
                ping -n 2 127.0.0.1 > nul
                """
          .trimIndent()
      } else {
        """
                #!/usr/bin/env sh
                echo "Starting FProxy on 127.0.0.1:$TEST_PORT"
                echo "READY"
                sleep 0.2
                """
          .trimIndent()
      }
    Files.writeString(script, content, StandardCharsets.UTF_8)
    val executableSet = script.toFile().setExecutable(true)
    if (!executableSet && !isWindows) {
      error("Failed to mark cryptad script as executable: $script")
    }
    return script
  }

  private fun writeWrapperConf(baseDir: Path): Path {
    val confDir = baseDir.resolve("conf")
    val logsDir = baseDir.resolve("logs")
    Files.createDirectories(confDir)
    Files.createDirectories(logsDir)
    val conf = confDir.resolve("wrapper.conf")
    val lines = listOf("# wrapper.conf", "wrapper.logfile=../logs/wrapper.log")
    Files.write(conf, lines, StandardCharsets.UTF_8)
    Files.writeString(logsDir.resolve("wrapper.log"), "", StandardCharsets.UTF_8)
    return conf
  }

  private fun setState(controller: LauncherController, state: AppState) {
    val stateFlow = getStateFlow(controller)
    stateFlow.value = state
  }

  private fun getPrivateState(controller: LauncherController): AppState =
    getStateFlow(controller).value

  @Suppress("kotlin:S6518")
  private fun setPrivateField(target: Any, fieldName: String, value: Any?) {
    val field = target.javaClass.getDeclaredField(fieldName)
    field.isAccessible = true
    field.set(target, value)
  }

  @Suppress("kotlin:S6518")
  private fun getStateFlow(controller: LauncherController): MutableStateFlow<AppState> {
    val field = controller.javaClass.getDeclaredField("_state")
    field.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    return field.get(controller) as MutableStateFlow<AppState>
  }

  private data class LogCollector(val lines: CopyOnWriteArrayList<String>)
}
