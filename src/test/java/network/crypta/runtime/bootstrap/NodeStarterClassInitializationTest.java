package network.crypta.runtime.bootstrap;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.support.ProcessPriority;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperListener;
import org.tanukisoftware.wrapper.WrapperManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;

@SuppressWarnings("java:S100")
class NodeStarterClassInitializationTest {

  @Test
  void main_whenClassIsFresh_registersWrapperBeforeInitializingNodeLogging() throws Exception {
    // Arrange
    List<String> calls = new ArrayList<>();
    AtomicReference<WrapperListener> listener = new AtomicReference<>();
    Logger nodeLogger = mock(Logger.class);
    URL classes = NodeStarter.class.getProtectionDomain().getCodeSource().getLocation();
    String[] args = {"--config-file", "cryptad.ini"};

    try (URLClassLoader loader =
            new FreshNodeStarterClassLoader(classes, getClass().getClassLoader());
        MockedStatic<LoggerFactory> logging =
            Mockito.mockStatic(LoggerFactory.class, CALLS_REAL_METHODS);
        MockedStatic<WrapperManager> wrapper = Mockito.mockStatic(WrapperManager.class);
        MockedStatic<ProcessPriority> priority = Mockito.mockStatic(ProcessPriority.class)) {
      logging
          .when(() -> LoggerFactory.getLogger(Mockito.<Class<?>>any()))
          .thenAnswer(
              invocation -> {
                Class<?> owner = invocation.getArgument(0);
                if (owner.getName().equals(NodeStarter.class.getName())) {
                  calls.add("node-logger");
                }
                return nodeLogger;
              });
      wrapper
          .when(WrapperManager::isControlledByNativeWrapper)
          .thenAnswer(
              _ -> {
                calls.add("wrapper-initialized");
                return false;
              });
      priority
          .when(ProcessPriority::enterBackgroundMode)
          .thenAnswer(
              _ -> {
                calls.add("priority");
                return true;
              });
      wrapper
          .when(() -> WrapperManager.start(Mockito.any(WrapperListener.class), Mockito.any()))
          .thenAnswer(
              invocation -> {
                calls.add("wrapper-start");
                listener.set(invocation.getArgument(0));
                return null;
              });

      // Act
      Class<?> fresh = Class.forName(NodeStarter.class.getName(), true, loader);
      fresh.getMethod("main", String[].class).invoke(null, (Object) args);

      // Assert
      assertEquals(List.of("wrapper-initialized", "wrapper-start"), calls);
      assertNotNull(listener.get());

      // Act
      assertEquals(7, listener.get().stop(7));
      assertEquals(9, listener.get().stop(9));

      // Assert
      assertEquals(List.of("wrapper-initialized", "wrapper-start", "node-logger"), calls);
      logging.verify(() -> LoggerFactory.getLogger(fresh), times(1));
      wrapper.verify(() -> WrapperManager.signalStopping(120000), times(2));
    }
  }

  private static final class FreshNodeStarterClassLoader extends URLClassLoader {
    private static final String NODE_STARTER = NodeStarter.class.getName();

    private FreshNodeStarterClassLoader(URL classes, ClassLoader parent) {
      super(new URL[] {classes}, parent);
    }

    @Override
    protected synchronized Class<?> loadClass(String name, boolean resolve)
        throws ClassNotFoundException {
      if (name.equals(NODE_STARTER) || name.startsWith(NODE_STARTER + "$")) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null) {
          loaded = findClass(name);
        }
        if (resolve) {
          resolveClass(loaded);
        }
        return loaded;
      }
      return super.loadClass(name, resolve);
    }
  }
}
