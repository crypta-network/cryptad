package network.crypta.support;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestSelector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Second level tree node. At the base we have RGA's. Then we have these, SRGAs containing RGAs.
 * Then we have SRGAs containing SRGAs.
 *
 * @author toad
 */
public class SectoredRandomGrabArraySimple<MyType, ChildType>
    extends SectoredRandomGrabArrayWithObject<
        MyType, ChildType, RandomGrabArrayWithObject<ChildType>> {

  static {
  }

  private static final Logger LOG = LoggerFactory.getLogger(SectoredRandomGrabArraySimple.class);

  public SectoredRandomGrabArraySimple(
      MyType object, RemoveRandomParent parent, ClientRequestSelector root) {
    super(object, parent, root);
  }

  /** Add directly to a RandomGrabArrayWithObject under us. */
  public void add(ChildType client, RandomGrabArrayItem item, ClientContext context) {
    synchronized (root) {
      RandomGrabArrayWithObject<ChildType> rga = getGrabber(client);
      if (rga == null) {
        if (LOG.isDebugEnabled())
          LOG.debug("Adding new RGAWithClient for " + client + " on " + this + " for " + item);
        rga = new RandomGrabArrayWithObject<>(client, this, root);
        addElement(client, rga);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Adding " + item + " to RGA " + rga + " for " + client);
      rga.add(item, context);
      if (context != null) {
        clearWakeupTime(context);
      }
      if (LOG.isDebugEnabled()) LOG.debug("Size now " + size() + " on " + this);
    }
  }
}
