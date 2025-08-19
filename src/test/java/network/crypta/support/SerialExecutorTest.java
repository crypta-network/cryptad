package network.crypta.support;

import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.junit.Test;

public class SerialExecutorTest {

  @Test
  public void testBlocking() {
    SerialExecutor exec = new SerialExecutor(NativeThread.PriorityLevel.NORM_PRIORITY.value);
    exec.start(new PooledExecutor(), "test");
    final MutableBoolean flag = new MutableBoolean();
    exec.execute(
        new PrioRunnable() {

          @Override
          public void run() {
            try {
              // Do nothing
            } finally {
              synchronized (flag) {
                flag.value = true;
                flag.notifyAll();
              }
            }
          }

          @Override
          public int getPriority() {
            return NativeThread.PriorityLevel.NORM_PRIORITY.value;
          }
        });
    synchronized (flag) {
      while (!flag.value) {
        try {
          flag.wait();
        } catch (InterruptedException e) {
          // Ignore
        }
      }
    }
  }
}
