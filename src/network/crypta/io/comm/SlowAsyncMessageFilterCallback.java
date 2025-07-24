package network.crypta.io.comm;

/**
 * AsyncMessageFilterCallback where the callbacks may do things that take significant time.
 */
public interface SlowAsyncMessageFilterCallback extends
        AsyncMessageFilterCallback {

    int getPriority();

}
