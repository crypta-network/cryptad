package network.crypta.node;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;

public interface BaseRequestThrottle {

  long DEFAULT_DELAY = MILLISECONDS.toMillis(200);
  long MAX_DELAY = MINUTES.toMillis(5);
  long MIN_DELAY = MILLISECONDS.toMillis(20);

  /** Get the current inter-request delay. */
  long getDelay();
}
