package network.crypta.clients.fcp;

import java.util.HashMap;
import network.crypta.client.InsertContext;
import network.crypta.client.async.BaseManifestPutter;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.HexUtil;
import network.crypta.support.Logger;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.DelayedFreeBucket;
import network.crypta.support.io.DelayedFreeRandomAccessBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import network.crypta.support.io.PaddedEphemerallyEncryptedBucket;
import network.crypta.support.io.PersistentTempFileBucket;
import network.crypta.support.io.TempBucketFactory;

public class PersistentPutDir extends FCPMessage {

  static final String name = "PersistentPutDir";

  final String identifier;
  final FreenetURI uri;
  final FreenetURI privateURI;
  final int verbosity;
  final short priorityClass;
  final Persistence persistence;
  final boolean global;
  private final HashMap<String, Object> manifestElements;
  final String defaultName;
  final String token;
  final boolean started;
  final int maxRetries;
  final boolean wasDiskPut;
  private final SimpleFieldSet cached;
  final boolean dontCompress;
  final String compressorDescriptor;
  final boolean realTime;
  final byte[] splitfileCryptoKey;
  final InsertContext.CompatibilityMode compatMode;

  public PersistentPutDir(
      String identifier,
      FreenetURI publicURI,
      FreenetURI privateURI,
      int verbosity,
      short priorityClass,
      Persistence persistence,
      boolean global,
      String defaultName,
      HashMap<String, Object> manifestElements,
      String token,
      boolean started,
      int maxRetries,
      boolean dontCompress,
      String compressorDescriptor,
      boolean wasDiskPut,
      boolean realTime,
      byte[] splitfileCryptoKey,
      InsertContext.CompatibilityMode cmode) {
    this.identifier = identifier;
    this.uri = publicURI;
    this.privateURI = privateURI;
    this.verbosity = verbosity;
    this.priorityClass = priorityClass;
    this.persistence = persistence;
    this.global = global;
    this.defaultName = defaultName;
    this.manifestElements = manifestElements;
    this.token = token;
    this.started = started;
    this.maxRetries = maxRetries;
    this.wasDiskPut = wasDiskPut;
    this.dontCompress = dontCompress;
    this.compressorDescriptor = compressorDescriptor;
    this.realTime = realTime;
    this.splitfileCryptoKey = splitfileCryptoKey;
    this.compatMode = cmode;
    cached = generateFieldSet();
  }

  private SimpleFieldSet generateFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false); // false because this can get HUGE
    fs.putSingle("Identifier", identifier);
    fs.putSingle("URI", uri.toString(false, false));
    if (privateURI != null) fs.putSingle("PrivateURI", privateURI.toString(false, false));
    fs.put("Verbosity", verbosity);
    fs.putSingle("Persistence", persistence.toString().toLowerCase());
    fs.put("PriorityClass", priorityClass);
    fs.put("Global", global);
    fs.putSingle("PutDirType", wasDiskPut ? "disk" : "complex");
    fs.putOverwrite("CompatibilityMode", compatMode.name());
    SimpleFieldSet files = new SimpleFieldSet(false);
    // Flatten the hierarchy, it can be reconstructed on restarting.
    // Storing it directly would be a PITA.
    // FIXME/RESOLVE: The new BaseManifestPutter's container mode does not hold the origin data,
    //                 after composing the PutHandlers (done in BaseManifestPutter), they are
    // 'lost':
    //                 A resumed half done container put can not get the complete file list from
    // BaseManifestPutter.
    //                 Is it really necessary to include the file list here?
    ManifestElement[] elements = BaseManifestPutter.flatten(manifestElements);
    fs.putSingle("DefaultName", defaultName);
    for (int i = 0; i < elements.length; i++) {
      String num = Integer.toString(i);
      ManifestElement e = elements[i];
      String mimeOverride = e.getMimeTypeOverride();
      SimpleFieldSet subset = new SimpleFieldSet(false);
      FreenetURI tempURI = e.getTargetURI();
      subset.putSingle("Name", e.getName());
      if (tempURI != null) {
        subset.putSingle("UploadFrom", "redirect");
        subset.putSingle("TargetURI", tempURI.toString());
      } else {
        Bucket data = e.getData();
        if (data instanceof DelayedFreeBucket bucket1) {
          data = bucket1.getUnderlying();
        } else if (data instanceof DelayedFreeRandomAccessBucket bucket) {
          data = bucket.getUnderlying();
        }
        subset.put("DataLength", e.getSize());
        if (mimeOverride != null) subset.putSingle("Metadata.ContentType", mimeOverride);
        // What to do with the bucket?
        // It is either a persistent encrypted bucket or a file bucket ...
        if (data == null) {
          Logger.error(
              this,
              "Bucket already freed: "
                  + e.getData()
                  + " for "
                  + e
                  + " for "
                  + e.getName()
                  + " for "
                  + identifier);
        } else if (data instanceof FileBucket bucket) {
          subset.putSingle("UploadFrom", "disk");
          subset.putSingle("Filename", bucket.getFile().getPath());
        } else if (data instanceof PaddedEphemerallyEncryptedBucket
            || data instanceof NullBucket
            || data instanceof PersistentTempFileBucket
            || data instanceof TempBucketFactory.TempBucket
            || data instanceof EncryptedRandomAccessBucket) {
          subset.putSingle("UploadFrom", "direct");
        } else {
          throw new IllegalStateException("Don't know what to do with bucket: " + data);
        }
      }
      files.put(num, subset);
    }
    files.put("Count", elements.length);
    fs.put("Files", files);
    if (token != null) fs.putSingle("ClientToken", token);
    fs.put("Started", started);
    fs.put("MaxRetries", maxRetries);
    fs.put("DontCompress", dontCompress);
    if (compressorDescriptor != null) fs.putSingle("Codecs", compressorDescriptor);
    fs.put("RealTime", realTime);
    if (splitfileCryptoKey != null)
      fs.putSingle("SplitfileCryptoKey", HexUtil.bytesToHex(splitfileCryptoKey));
    return fs;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    return cached;
  }

  @Override
  public String getName() {
    return name;
  }

  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    throw new MessageInvalidException(
        ProtocolErrorMessage.INVALID_MESSAGE,
        "PersistentPut goes from server to client not the other way around",
        identifier,
        global);
  }
}
