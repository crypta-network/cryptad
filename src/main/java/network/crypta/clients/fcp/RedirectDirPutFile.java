package network.crypta.clients.fcp;

import java.net.MalformedURLException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RedirectDirPutFile extends DirPutFile {
  private static final Logger LOG = LoggerFactory.getLogger(RedirectDirPutFile.class);

  final FreenetURI targetURI;

  // Legacy threshold callback removed.

  public static RedirectDirPutFile create(
      String name,
      String contentTypeOverride,
      SimpleFieldSet subset,
      String identifier,
      boolean global)
      throws MessageInvalidException {
    String target = subset.get("TargetURI");
    if (target == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "TargetURI missing but UploadFrom=redirect",
          identifier,
          global);
    FreenetURI targetURI;
    try {
      targetURI = new FreenetURI(target);
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, "Invalid TargetURI: " + e, identifier, global);
    }
    if (LOG.isDebugEnabled()) LOG.debug("targetURI = " + targetURI);
    String mimeType;
    if (contentTypeOverride != null) mimeType = contentTypeOverride;
    else mimeType = guessMIME(name);
    return new RedirectDirPutFile(name, mimeType, targetURI);
  }

  public RedirectDirPutFile(String name, String mimeType, FreenetURI targetURI) {
    super(name, mimeType);
    this.targetURI = targetURI;
  }

  @Override
  public RandomAccessBucket getData() {
    return null;
  }

  @Override
  public ManifestElement getElement() {
    return new ManifestElement(name, targetURI, getMIMEType());
  }
}
