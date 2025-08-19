package network.crypta.client.async;

import java.io.Serial;
import java.io.Serializable;
import network.crypta.node.RequestClient;

public abstract class BaseClientGetter extends ClientRequester
    implements GetCompletionCallback, Serializable {

  @Serial private static final long serialVersionUID = 1L;

  protected BaseClientGetter(short priorityClass, RequestClient requestClient) {
    super(priorityClass, requestClient);
  }

  /** Required because we implement {@link Serializable}. */
  protected BaseClientGetter() {}
}
