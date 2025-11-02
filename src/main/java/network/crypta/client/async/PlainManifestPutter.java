package network.crypta.client.async;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.InsertContext;
import network.crypta.client.Metadata;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.ResumeFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * plain/dumb manifest putter: every file item is a redirect (no containers at all)
 *
 * <p>default doc:<br>
 * defaultName is just the name, without any '/'!<br>
 * each item &lt;defaultName&gt; is the default doc in the corresponding dir.
 */
public class PlainManifestPutter extends BaseManifestPutter {
  private static final Logger LOG = LoggerFactory.getLogger(PlainManifestPutter.class);

  @Serial private static final long serialVersionUID = 1L;

  static {
  }

  public PlainManifestPutter(
      ClientPutCallback clientCallback,
      HashMap<String, Object> manifestElements,
      short prioClass,
      FreenetURI target,
      String defaultName,
      InsertContext ctx,
      boolean getCHKOnly,
      boolean earlyEncode,
      boolean persistent,
      byte[] forceCryptoKey,
      ClientContext context)
      throws TooManyFilesInsertException {
    super(
        new InitParams()
            .withCb(clientCallback)
            .withManifestElements(manifestElements)
            .withPrioClass(prioClass)
            .withTarget(target)
            .withDefaultName(defaultName)
            .withCtx(ctx)
            .withRandomiseCryptoKeys(ClientPutter.randomiseSplitfileKeys(target, ctx))
            .withForceCryptoKey(forceCryptoKey)
            .withContext(context));
  }

  @Override
  protected void makePutHandlers(HashMap<String, Object> manifestElements, String defaultName) {
    if (LOG.isTraceEnabled()) LOG.trace("Root map : " + manifestElements.size() + " elements");
    makePutHandlers(getRootBuilder(), manifestElements, defaultName);
  }

  private void makePutHandlers(
      FreeFormBuilder builder, HashMap<String, Object> manifestElements, Object defaultName) {
    for (Map.Entry<String, Object> entry : manifestElements.entrySet()) {
      String name = entry.getKey();
      Object o = entry.getValue();
      if (o instanceof HashMap) {
        HashMap<String, Object> subMap = Metadata.forceMap(o);
        builder.pushCurrentDir();
        builder.makeSubDirCD(name);
        makePutHandlers(builder, subMap, defaultName);
        builder.popCurrentDir();
        if (LOG.isTraceEnabled())
          LOG.trace("Sub map for " + name + " : " + subMap.size() + " elements");
      } else {
        ManifestElement element = (ManifestElement) o;
        builder.addElement(name, element, name.equals(defaultName));
      }
    }
  }

  @Override
  public void innerOnResume(ClientContext context) throws ResumeFailedException {
    super.innerOnResume(context);
    notifyClients(context);
  }
}
