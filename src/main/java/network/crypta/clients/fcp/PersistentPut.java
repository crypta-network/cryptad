package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.client.InsertContext;
import network.crypta.clients.fcp.ClientPutBase.UploadFrom;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;

public class PersistentPut extends FCPMessage {

  static final String name = "PersistentPut";

  final String identifier;
  final FreenetURI uri;
  final FreenetURI privateURI;
  final int verbosity;
  final short priorityClass;
  final UploadFrom uploadFrom;
  final Persistence persistence;
  final File origFilename;
  final String mimeType;
  final boolean global;
  final FreenetURI targetURI;
  final long size;
  final String token;
  final boolean started;
  final int maxRetries;
  final String targetFilename;
  final boolean binaryBlob;
  final InsertContext.CompatibilityMode compatMode;
  final boolean dontCompress;
  final boolean realTime;
  final byte[] splitfileCryptoKey;
  final String compressorDescriptor;

  public PersistentPut(
      String identifier,
      FreenetURI publicURI,
      FreenetURI privateURI,
      int verbosity,
      short priorityClass,
      UploadFrom uploadFrom,
      FreenetURI targetURI,
      Persistence persistence,
      File origFilename,
      String mimeType,
      boolean global,
      long size,
      String clientToken,
      boolean started,
      int maxRetries,
      String targetFilename,
      boolean binaryBlob,
      InsertContext.CompatibilityMode compatMode,
      boolean dontCompress,
      String compressorDescriptor,
      boolean realTime,
      byte[] splitfileCryptoKey) {
    this.identifier = identifier;
    this.uri = publicURI;
    this.privateURI = privateURI;
    this.verbosity = verbosity;
    this.priorityClass = priorityClass;
    this.uploadFrom = uploadFrom;
    this.targetURI = targetURI;
    this.persistence = persistence;
    this.origFilename = origFilename;
    this.mimeType = mimeType;
    this.global = global;
    this.size = size;
    this.token = clientToken;
    this.started = started;
    this.maxRetries = maxRetries;
    this.targetFilename = targetFilename;
    this.binaryBlob = binaryBlob;
    this.compatMode = compatMode;
    this.dontCompress = dontCompress;
    this.compressorDescriptor = compressorDescriptor;
    this.realTime = realTime;
    this.splitfileCryptoKey = splitfileCryptoKey;
  }

  @Override
  public SimpleFieldSet getFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("Identifier", identifier);
    fs.putSingle("URI", uri.toString(false, false));
    if (privateURI != null) fs.putSingle("PrivateURI", privateURI.toString(false, false));
    fs.put("Verbosity", verbosity);
    fs.put("PriorityClass", priorityClass);
    fs.putSingle("UploadFrom", uploadFrom.toString().toLowerCase());
    fs.putSingle("Persistence", persistence.toString().toLowerCase());
    if (origFilename != null) fs.putSingle("Filename", origFilename.getAbsolutePath());
    if (targetURI != null) fs.putSingle("TargetURI", targetURI.toString());
    if (mimeType != null) fs.putSingle("Metadata.ContentType", mimeType);
    fs.put("Global", global);
    if (size != -1) fs.put("DataLength", size);
    if (token != null) fs.putSingle("ClientToken", token);
    fs.put("Started", started);
    fs.put("MaxRetries", maxRetries);
    if (targetFilename != null) fs.putSingle("TargetFilename", targetFilename);
    if (binaryBlob) fs.put("BinaryBlob", binaryBlob);
    fs.putOverwrite("CompatibilityMode", compatMode.name());
    fs.put("DontCompress", dontCompress);
    if (compressorDescriptor != null) fs.putSingle("Codecs", compressorDescriptor);
    fs.put("RealTime", realTime);
    if (splitfileCryptoKey != null)
      fs.putSingle("SplitfileCryptoKey", HexUtil.bytesToHex(splitfileCryptoKey));
    return fs;
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
