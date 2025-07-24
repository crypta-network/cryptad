package network.crypta.support;

import network.crypta.support.MutableBoolean;
import network.crypta.support.PooledExecutor;
import network.crypta.support.SerialExecutor;
import org.junit.Test;

import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;

public class SerialExecutorTest {

    @Test
    public void testBlocking() {
        SerialExecutor exec = new SerialExecutor(NativeThread.NORM_PRIORITY);
        exec.start(new PooledExecutor(), "test");
        final MutableBoolean flag = new MutableBoolean();
        exec.execute(new PrioRunnable() {

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
                return NativeThread.NORM_PRIORITY;
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
