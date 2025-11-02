package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.ClientRequestScheduler.SchedulerMode;
import network.crypta.config.Config;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.StringCallback;
import network.crypta.support.math.BootstrappingDecayingRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates request starters and client schedulers for CHK/SSK fetches and inserts.
 *
 * <p>Wires four flows per key type (CHK and SSK): fetch (request) vs insert, and bulk vs real-time.
 * Each flow has its own {@link RequestStarter}, {@link BaseRequestThrottle} and {@link
 * ClientRequestScheduler}. The group also maintains several {@link ThrottleWindowManager} instances
 * that adapt concurrency based on observed round-trip times (RTT) and overload events.
 *
 * <p>Thread-safety: public methods are safe to call from the node's scheduling threads. The inner
 * throttle synchronizes state changes where required. Methods that only read state are not
 * synchronized.
 */
public class RequestStarterGroup {
  private static final Logger LOG = LoggerFactory.getLogger(RequestStarterGroup.class);

  // Scheduler identifiers used in multiple places
  private static final String CHK_REQUESTER_NAME = "CHKrequester";
  private static final String CHK_INSERTER_NAME = "CHKinserter";
  private static final String SSK_REQUESTER_NAME = "SSKrequester";
  private static final String SSK_INSERTER_NAME = "SSKinserter";

  private final ThrottleWindowManager throttleWindowBulk;
  private final ThrottleWindowManager throttleWindowRT;
  // These are used for diagnostic reporting (stats panels, logs)
  private final ThrottleWindowManager throttleWindowCHK;
  private final ThrottleWindowManager throttleWindowSSK;
  private final ThrottleWindowManager throttleWindowInsert;
  private final ThrottleWindowManager throttleWindowRequest;
  final MyRequestThrottle chkRequestThrottleBulk;
  final RequestStarter chkRequestStarterBulk;
  final MyRequestThrottle chkInsertThrottleBulk;
  final RequestStarter chkInsertStarterBulk;
  final MyRequestThrottle sskRequestThrottleBulk;
  final RequestStarter sskRequestStarterBulk;
  final MyRequestThrottle sskInsertThrottleBulk;
  final RequestStarter sskInsertStarterBulk;

  final MyRequestThrottle chkRequestThrottleRT;
  final RequestStarter chkRequestStarterRT;
  final MyRequestThrottle chkInsertThrottleRT;
  final RequestStarter chkInsertStarterRT;
  final MyRequestThrottle sskRequestThrottleRT;
  final RequestStarter sskRequestStarterRT;
  final MyRequestThrottle sskInsertThrottleRT;
  final RequestStarter sskInsertStarterRT;

  /** Scheduler for CHK fetches in bulk mode. */
  public final ClientRequestScheduler chkFetchSchedulerBulk;

  /** Scheduler for CHK inserts in bulk mode. */
  public final ClientRequestScheduler chkPutSchedulerBulk;

  /** Scheduler for SSK fetches in bulk mode. */
  public final ClientRequestScheduler sskFetchSchedulerBulk;

  /** Scheduler for SSK inserts in bulk mode. */
  public final ClientRequestScheduler sskPutSchedulerBulk;

  /** Scheduler for CHK fetches in real-time mode. */
  public final ClientRequestScheduler chkFetchSchedulerRT;

  /** Scheduler for CHK inserts in real-time mode. */
  public final ClientRequestScheduler chkPutSchedulerRT;

  /** Scheduler for SSK fetches in real-time mode. */
  public final ClientRequestScheduler sskFetchSchedulerRT;

  /** Scheduler for SSK inserts in real-time mode. */
  public final ClientRequestScheduler sskPutSchedulerRT;

  private final NodeStats stats;

  RequestStarterGroup(
      Node node,
      NodeClientCore core,
      int portNumber,
      RandomSource random,
      Config config,
      SimpleFieldSet fs,
      ClientContext ctx)
      throws InvalidConfigValueException {
    SubConfig schedulerConfig = config.createSubConfig("node.scheduler");
    this.stats = core.getNodeStats();

    throttleWindowBulk =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindow"), node);
    throttleWindowRT =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowRT"), node);

    throttleWindowCHK =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowCHK"), node);
    throttleWindowSSK =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowSSK"), node);
    throttleWindowInsert =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowInsert"), node);
    throttleWindowRequest =
        new ThrottleWindowManager(
            2.0, fs == null ? null : fs.subset("ThrottleWindowRequest"), node);
    chkRequ
[... content truncated for brevity ...]
  public void setGlobalSalt(byte[] salt) {
    chkFetchSchedulerBulk.startCore(salt);
    sskFetchSchedulerBulk.startCore(salt);
    chkPutSchedulerBulk.startCore(salt);
    sskPutSchedulerBulk.startCore(salt);
    chkFetchSchedulerRT.startCore(salt);
    sskFetchSchedulerRT.startCore(salt);
    chkPutSchedulerRT.startCore(salt);
    sskPutSchedulerRT.startCore(salt);
  }
}
