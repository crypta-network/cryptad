package network.crypta.node;

import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class UIDTraceLogger {
  private static final Logger LOG = LoggerFactory.getLogger("network.crypta.uidtrace");

  private UIDTraceLogger() {}

  static void log(String event, UIDTag tag) {
    log(event, tag, null);
  }

  static void log(String event, UIDTag tag, Supplier<String> detailsSupplier) {
    if (!LOG.isInfoEnabled()) return;
    String details = detailsSupplier == null ? "" : detailsSupplier.get();
    if (details == null || details.isEmpty()) {
      details = "";
    } else {
      details = " " + details;
    }
    LOG.info(
        "event={} uid={} tag={} local={} originLocal={} rt={} ssk={} insert={} offer={}{}",
        event,
        tag.uid,
        tag.getClass().getSimpleName(),
        tag.isLocal(),
        tag.wasLocal(),
        tag.realTimeFlag,
        tag.isSSK(),
        tag.isInsert(),
        tag.isOfferReply(),
        details);
  }
}
