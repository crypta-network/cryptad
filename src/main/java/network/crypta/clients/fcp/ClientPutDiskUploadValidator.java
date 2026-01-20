package network.crypta.clients.fcp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.crypt.SHA256;
import network.crypta.node.NodeClientCore;
import network.crypta.support.Base64;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates disk upload permissions and salted hash constraints for {@link ClientPut}.
 *
 * <p>The validator centralizes DDA checks, salted hash decoding, and checksum verification so the
 * request class can focus on lifecycle management. Methods are stateless and reusable across
 * transient and persistent inserts.
 */
final class ClientPutDiskUploadValidator {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutDiskUploadValidator.class);

  private ClientPutDiskUploadValidator() {}

  static void validatePersistentDiskUpload(NodeClientCore core, File origFilename)
      throws NotAllowedException, IOException {
    if (!core.allowUploadFrom(origFilename)) {
      throw new NotAllowedException();
    }
    if (!(origFilename.exists() && origFilename.canRead())) {
      throw new FileNotFoundException();
    }
  }

  static DiskUploadContext validateDiskUpload(
      FCPConnectionHandler handler, ClientPutMessage message, String identifier, boolean global)
      throws MessageInvalidException {
    if (message.uploadFromType != ClientPutBase.UploadFrom.DISK) {
      return DiskUploadContext.empty();
    }
    if (!handler.getServer().getCore().allowUploadFrom(message.origFilename)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "Not allowed to upload from " + message.origFilename,
          identifier,
          global);
    }
    if (message.fileHash != null) {
      String salt =
          handler.getConnectionIdentifierUUID().toString() + '-' + message.identifier + '-';
      byte[] saltedHash = decodeFileHash(message.fileHash, identifier, global);
      return new DiskUploadContext(salt, saltedHash);
    }
    if (!handler.ddaAccessController().allowDDAFrom(message.origFilename, false)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED,
          "Not allowed to upload from "
              + message.origFilename
              + ". Have you done a testDDA previously ?",
          identifier,
          global);
    }
    return DiskUploadContext.empty();
  }

  static void verifySaltedHash(
      DiskUploadContext diskContext, RandomAccessBucket bucket, String identifier, boolean global)
      throws MessageInvalidException {
    if (!diskContext.hasSalt()) {
      return;
    }
    MessageDigest md = SHA256.getMessageDigest();
    md.update(diskContext.salt().getBytes(StandardCharsets.UTF_8));
    byte[] foundHash;
    try (InputStream is = bucket.getInputStream()) {
      SHA256.hash(is, md);
      foundHash = md.digest();
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.COULD_NOT_READ_FILE,
          "Unable to access file: " + e,
          identifier,
          global);
    }
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "FileHash result : we found {} and were given {}.",
          Base64.encode(foundHash),
          Base64.encode(diskContext.saltedHash()));
    }
    if (!Arrays.equals(diskContext.saltedHash(), foundHash)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.DIRECT_DISK_ACCESS_DENIED,
          "The hash doesn't match! (salt used : \"" + diskContext.salt() + "\")",
          identifier,
          global);
    }
  }

  private static byte[] decodeFileHash(String encoded, String identifier, boolean global)
      throws MessageInvalidException {
    try {
      return Base64.decodeStandard(encoded);
    } catch (IllegalBase64Exception _) {
      try {
        return Base64.decode(encoded);
      } catch (IllegalBase64Exception _) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INVALID_FIELD,
            "Can't base64 decode " + ClientPutBase.FILE_HASH,
            identifier,
            global);
      }
    }
  }
}

record DiskUploadContext(String salt, byte[] saltedHash) {
  private static final DiskUploadContext EMPTY = new DiskUploadContext(null, null);

  static DiskUploadContext empty() {
    return EMPTY;
  }

  boolean hasSalt() {
    return salt != null;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DiskUploadContext(String otherSalt, byte[] otherHash))) return false;
    return Objects.equals(salt, otherSalt) && Arrays.equals(saltedHash, otherHash);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(salt);
    result = 31 * result + Arrays.hashCode(saltedHash);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "DiskUploadContext[salt="
        + salt
        + ", saltedHash="
        + (saltedHash == null ? "null" : Arrays.toString(saltedHash))
        + ']';
  }
}
