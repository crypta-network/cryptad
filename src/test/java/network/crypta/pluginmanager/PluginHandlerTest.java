package network.crypta.pluginmanager;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PluginHandlerTest {

  @Test
  void startPlugin_whenThreadlessPlugin_runsPluginThenRegistersAndRestoresContextClassLoader() {
    // Arrange
    PluginManager pluginManager = mock(PluginManager.class);
    PluginInfoWrapper pluginInfo = mock(PluginInfoWrapper.class);
    PluginRespirator respirator = mock(PluginRespirator.class);

    List<String> events = new ArrayList<>();
    RecordingPlugin plugin = new RecordingPlugin(events);
    when(pluginInfo.getPlugin()).thenReturn(plugin);
    when(pluginInfo.isThreadlessPlugin()).thenReturn(true);
    when(pluginInfo.getPluginRespirator()).thenReturn(respirator);

    doAnswer(
            invocation -> {
              events.add("register");
              return null;
            })
        .when(pluginManager)
        .register(pluginInfo);

    ClassLoader original = Thread.currentThread().getContextClassLoader();
    ClassLoader oldContext = new ClassLoader(original) {};
    Thread.currentThread().setContextClassLoader(oldContext);

    try {
      // Act
      PluginHandler.startPlugin(pluginManager, pluginInfo);

      // Assert
      assertSame(
          plugin.getClass().getClassLoader(),
          plugin.contextClassLoaderAtRun,
          "Threadless plugin should run with its class loader as the context class loader");
      assertSame(respirator, plugin.seenRespirator, "Plugin should receive the respirator");
      assertSame(
          oldContext,
          Thread.currentThread().getContextClassLoader(),
          "startPlugin should restore the original context class loader");

      InOrder inOrder = inOrder(pluginManager);
      inOrder.verify(pluginManager).register(pluginInfo);

      assertEquals(
          List.of("runPlugin", "register"),
          events,
          "Threadless plugins should be run before being registered");
      verify(pluginInfo, never()).setThread(any(Thread.class));
      verify(pluginManager, never()).getTicker();
    } finally {
      Thread.currentThread().setContextClassLoader(original);
    }
  }

  @Test
  void startPlugin_whenThreadlessPluginAndRunThrows_restoresContextClassLoaderAndPropagates() {
    // Arrange
    PluginManager pluginManager = mock(PluginManager.class);
    PluginInfoWrapper pluginInfo = mock(PluginInfoWrapper.class);
    PluginRespirator respirator = mock(PluginRespirator.class);

    RuntimeException boom = new RuntimeException("boom");
    FredPlugin plugin = mock(FredPlugin.class);
    when(pluginInfo.getPlugin()).thenReturn(plugin);
    when(pluginInfo.isThreadlessPlugin()).thenReturn(true);
    when(pluginInfo.getPluginRespirator()).thenReturn(respirator);
    doAnswer(
            invocation -> {
              throw boom;
            })
        .when(plugin)
        .runPlugin(respirator);

    ClassLoader original = Thread.currentThread().getContextClassLoader();
    ClassLoader oldContext = new ClassLoader(original) {};
    Thread.currentThread().setContextClassLoader(oldContext);

    try {
      // Act + Assert
      RuntimeException thrown =
          assertThrows(
              RuntimeException.class, () -> PluginHandler.startPlugin(pluginManager, pluginInfo));
      assertSame(boom, thrown, "Threadless runPlugin exceptions should be propagated");
      assertSame(
          oldContext,
          Thread.currentThread().getContextClassLoader(),
          "startPlugin should restore the original context class loader even on exception");

      verify(pluginManager, never()).register(pluginInfo);
      verify(pluginInfo, never()).setThread(any(Thread.class));
    } finally {
      Thread.currentThread().setContextClassLoader(original);
    }
  }

  @Test
  void startPlugin_whenThreadedPlugin_queuesTimedJobAndJobStartsDaemonThread() throws Exception {
    // Arrange
    PluginManager pluginManager = mock(PluginManager.class);
    Ticker ticker = mock(Ticker.class);
    when(pluginManager.getTicker()).thenReturn(ticker);

    PluginInfoWrapper pluginInfo = mock(PluginInfoWrapper.class);
    PluginRespirator respirator = mock(PluginRespirator.class);
    RecordingPlugin plugin = new RecordingPlugin(new ArrayList<>());

    when(pluginInfo.getPlugin()).thenReturn(plugin);
    when(pluginInfo.isThreadlessPlugin()).thenReturn(false);
    when(pluginInfo.getPluginRespirator()).thenReturn(respirator);

    AtomicReference<Thread> createdThread = new AtomicReference<>();
    doAnswer(
            invocation -> {
              Thread thread = invocation.getArgument(0, Thread.class);
              createdThread.set(thread);
              return null;
            })
        .when(pluginInfo)
        .setThread(any(Thread.class));

    CountDownLatch pluginFinished = new CountDownLatch(1);
    doAnswer(
            invocation -> {
              pluginFinished.countDown();
              return null;
            })
        .when(pluginManager)
        .removePlugin(pluginInfo);

    ArgumentCaptor<Runnable> jobCaptor = ArgumentCaptor.forClass(Runnable.class);
    doNothing().when(ticker).queueTimedJob(jobCaptor.capture(), eq(0L));

    ClassLoader original = Thread.currentThread().getContextClassLoader();
    ClassLoader oldContext = new ClassLoader(original) {};
    Thread.currentThread().setContextClassLoader(oldContext);

    try {
      // Act
      PluginHandler.startPlugin(pluginManager, pluginInfo);

      // Assert (scheduling)
      verify(ticker).queueTimedJob(any(Runnable.class), eq(0L));
      assertSame(
          oldContext,
          Thread.currentThread().getContextClassLoader(),
          "startPlugin should restore the original context class loader after scheduling");

      Runnable queuedJob = jobCaptor.getValue();
      assertNotNull(queuedJob, "startPlugin should enqueue a job to start the plugin thread");

      // Act (simulate ticker execution)
      queuedJob.run();

      Thread thread = createdThread.get();
      assertNotNull(thread, "startPlugin should set the created plugin thread on the wrapper");
      assertTrue(thread.isDaemon(), "Plugin thread should be created as a daemon thread");

      boolean completed = pluginFinished.await(2, TimeUnit.SECONDS);
      assertTrue(completed, "Plugin thread should complete quickly in this test");
      thread.join(2_000);

      assertSame(
          plugin.getClass().getClassLoader(),
          plugin.contextClassLoaderAtRun,
          "Threaded plugin should run with its class loader as the context class loader");
      assertSame(respirator, plugin.seenRespirator, "Plugin should receive the respirator");

      InOrder inOrder = inOrder(pluginManager, pluginInfo);
      inOrder.verify(pluginManager).register(pluginInfo);
      inOrder.verify(pluginInfo).unregister(pluginManager, false);
      inOrder.verify(pluginManager).removePlugin(pluginInfo);
    } finally {
      Thread.currentThread().setContextClassLoader(original);
    }
  }

  @Test
  void startPlugin_whenThreadedPluginAndRunThrows_unregistersAndRemovesPlugin() throws Exception {
    // Arrange
    PluginManager pluginManager = mock(PluginManager.class);
    Ticker ticker = mock(Ticker.class);
    when(pluginManager.getTicker()).thenReturn(ticker);

    PluginInfoWrapper pluginInfo = mock(PluginInfoWrapper.class);
    PluginRespirator respirator = mock(PluginRespirator.class);

    RuntimeException boom = new RuntimeException("boom");
    FredPlugin plugin = mock(FredPlugin.class);
    when(pluginInfo.getPlugin()).thenReturn(plugin);
    when(pluginInfo.isThreadlessPlugin()).thenReturn(false);
    when(pluginInfo.getPluginRespirator()).thenReturn(respirator);
    doAnswer(
            invocation -> {
              throw boom;
            })
        .when(plugin)
        .runPlugin(respirator);

    AtomicReference<Thread> createdThread = new AtomicReference<>();
    doAnswer(
            invocation -> {
              Thread thread = invocation.getArgument(0, Thread.class);
              createdThread.set(thread);
              return null;
            })
        .when(pluginInfo)
        .setThread(any(Thread.class));

    CountDownLatch removed = new CountDownLatch(1);
    doAnswer(
            invocation -> {
              removed.countDown();
              return null;
            })
        .when(pluginManager)
        .removePlugin(pluginInfo);

    ArgumentCaptor<Runnable> jobCaptor = ArgumentCaptor.forClass(Runnable.class);
    doNothing().when(ticker).queueTimedJob(jobCaptor.capture(), eq(0L));

    // Act
    PluginHandler.startPlugin(pluginManager, pluginInfo);
    jobCaptor.getValue().run();

    // Assert
    boolean removedCalled = removed.await(2, TimeUnit.SECONDS);
    assertTrue(removedCalled, "Plugin should be removed even if runPlugin throws");

    Thread thread = createdThread.get();
    assertNotNull(thread, "startPlugin should set the created plugin thread on the wrapper");
    thread.join(2_000);

    InOrder inOrder = inOrder(pluginManager, pluginInfo);
    inOrder.verify(pluginManager).register(pluginInfo);
    inOrder.verify(pluginInfo).unregister(pluginManager, false);
    inOrder.verify(pluginManager).removePlugin(pluginInfo);
  }

  private static final class RecordingPlugin implements FredPlugin {
    private final List<String> events;
    private PluginRespirator seenRespirator;
    private ClassLoader contextClassLoaderAtRun;

    private RecordingPlugin(List<String> events) {
      this.events = events;
    }

    @Override
    public void terminate() {
      // Not exercised by PluginHandler.
    }

    @Override
    public void runPlugin(PluginRespirator pr) {
      events.add("runPlugin");
      seenRespirator = pr;
      contextClassLoaderAtRun = Thread.currentThread().getContextClassLoader();
    }
  }
}
