package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Persister implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(Persister.class);

  static {
  }

  static final long PERIOD = MINUTES.toMillis(15);

  Persister(Persistable t, File persistTemp, File persistTarget, Ticker ps) {
    this.persistable = t;
    this.persistTemp = persistTemp;
    this.persistTarget = persistTarget;
    this.ps = ps;
  }

  // Subclass must set the others later
  protected Persister(Persistable t, Ticker ps) {
    this.persistable = t;
    this.ps = ps;
  }

  final Persistable persistable;
  private final Ticker ps;
  File persistTemp;
  File persistTarget;
  private boolean started;

  void interrupt() {
    synchronized (this) {
      notifyAll();
    }
  }

  @Override
  public void run() {
    try {
      persistThrottle();
    } catch (Throwable t) {
      LOG.error("Caught in ThrottlePersister: " + t, t);
      System.err.println("Caught in ThrottlePersister: " + t);
      t.printStackTrace();
      System.err.println("Will restart ThrottlePersister...");
    }
    ps.queueTimedJob(this, PERIOD);
  }

  private void persistThrottle() {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Trying to persist throttles...");
    }
    SimpleFieldSet fs = persistable.persistThrottlesToFieldSet();
    try (FileOutputStream fos = new FileOutputStream(persistTemp)) {
      fs.writeToBigBuffer(fos);
    } catch (FileNotFoundException e) {
      LOG.error("Could not store throttle data to disk: " + e, e);
    } catch (IOException e) {
      persistTemp.delete();
    }
    try {
      FileUtil.moveTo(persistTemp, persistTarget);
    } catch (Exception e) {
      LOG.error("Could not move temp file to target: " + e, e);
    }
  }

  public SimpleFieldSet read() {
    SimpleFieldSet throttleFS = null;
    try {
      throttleFS = SimpleFieldSet.readFrom(persistTarget, false, true);
    } catch (IOException e) {
      try {
        throttleFS = SimpleFieldSet.readFrom(persistTemp, false, true);
      } catch (FileNotFoundException e1) {
        // Ignore
      } catch (IOException e1) {
        if (persistTarget.length() > 0 || persistTemp.length() > 0)
          LOG.error(
              "Could not read "
                  + persistTarget
                  + " ("
                  + e
                  + ") and could not read "
                  + persistTemp
                  + " either ("
                  + e1
                  + ')');
      }
    }
    return throttleFS;
  }

  public void start() {
    synchronized (this) {
      if (started) {
        LOG.warn("Already started: {}", this);
        return;
      }
      started = true;
    }
    SemiOrderedShutdownHook.get()
        .addEarlyJob(
            new Thread() {

              public void run() {
                System.out.println("Writing " + persistTarget + " on shutdown");
                persistThrottle();
              }
            });
    run();
  }
}
