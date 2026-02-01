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
 * Validates disk-backed upload permissions and salted hash constraints for {@link ClientPut}.
 *
 * <p>This helper consolidates the checks that gate disk uploads for FCP requests. Callers use it to
 * enforce server-side DDA policy, to decode and validate the optional salted hash submitted by a
 * client, and to confirm that a disk file is readable before a persistent insert is accepted. The
 * API is intentionally stateless: each method reads inputs, performs synchronous validation, and
 * reports success or failure through exceptions rather than maintaining internal state.
 *
 * <p>All methods assume they are invoked by trusted request handlers that already constructed the
 * relevant {@link ClientPutMessage} or request metadata. The validation work is CPU-bound and uses
 * streaming reads only when a salted hash must be verified, so it is safe to call from request
 * setup code without additional synchronization.
 *
 * <ul>
 *   <li>Checks whether a disk upload is allowed by node policy and DDA rules.
 *   <li>Decodes and verifies salted SHA-256 hashes when provided by clients.
 *   <li>Produces {@link DiskUploadContext} instances for downstream verification steps.
 * </ul>
 *
 * @see ClientPut
 * @see DiskUploadContext
 */
final class ClientPutDiskUploadValidator {
  /** Logger used for optional salted hash verification diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutDiskUploadValidator.class);

  /** Prevents instantiation; this class only exposes static validators. */
  private ClientPutDiskUploadValidator() {}

  /**
   * Validates a persistent disk upload against core permissions and file readability.
   *
   * <p>This method is used for persistent inserts where the node must be able to reopen the source
   * file across restarts. It first checks the node policy via {@link
   * NodeClientCore#allowUploadFrom} and then verifies that the file exists and can be read. It
   * performs no hashing and does not mutate the input file.
   *
   * @param core node core used to evaluate disk upload policy; must not be {@code null}.
   * @param origFilename original file submitted by the client; must not be {@code null}.
   * @throws NotAllowedException when the node policy disallows the requested disk upload.
   * @throws IOException when the file does not exist or cannot be read.
   */
  static void validatePersistentDiskUpload(NodeClientCore core, File origFilename)
      throws NotAllowedException, IOException {
    if (!core.allowUploadFrom(origFilename)) {
      throw new NotAllowedException();
    }
    if (!(origFilename.exists() && origFilename.canRead())) {
      throw new FileNotFoundException();
    }
  }

  /**
   * Validates a disk upload request coming from a live FCP connection.
   *
   * <p>The method enforces DDA rules for connection-scoped inserts. If the request does not use a
   * disk source, an empty context is returned immediately. When a client provides a file hash, the
   * hash is decoded and returned in a {@link DiskUploadContext} so later steps can verify it
   * against the upload bucket. When no hash is provided, DDA access is validated directly.
   *
   * @param handler active connection handler that supplies policy and identifiers; must not be
   *     {@code null}.
   * @param message parsed FCP put message containing upload fields; must not be {@code null}.
   * @param identifier request identifier used for error reporting; must not be {@code null}.
   * @param global whether the request is in the global queue for error context reporting.
   * @return a {@link DiskUploadContext} containing salted hash data or an empty context when
   *     unused.
   * @throws MessageInvalidException when the request violates DDA rules or contains bad hash data.
   */
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

  /**
   * Verifies a salted hash by reading the provided bucket and comparing the digest.
   *
   * <p>If the {@link DiskUploadContext} does not include a salt, the method returns immediately. If
   * a salt is present, the bucket is read once to compute the SHA-256 digest and compared to the
   * provided salted hash. The bucket is not mutated; only an input stream is opened and closed.
   *
   * @param diskContext salted hash context created during validation; must not be {@code null}.
   * @param bucket random-access bucket containing the upload payload; must not be {@code null}.
   * @param identifier request identifier used for error reporting; must not be {@code null}.
   * @param global whether the request is in the global queue for error context reporting.
   * @throws MessageInvalidException when the bucket cannot be read or the hash does not match.
   */
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

  /**
   * Decodes a client-provided hash using the supported base64 variants.
   *
   * <p>The method first attempts standard base64 decoding, then falls back to the alternate decoder
   * used by older clients. Any decoding failure results in a {@link MessageInvalidException} with a
   * protocol error suitable for forwarding to the requester.
   *
   * @param encoded base64-encoded hash string supplied by the client; must not be {@code null}.
   * @param identifier request identifier used for error reporting; must not be {@code null}.
   * @param global whether the request is in the global queue for error context reporting.
   * @return decoded hash bytes suitable for comparison with computed digests.
   * @throws MessageInvalidException when the hash cannot be decoded by any supported variant.
   */
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

/**
 * Encapsulates the salted hash metadata for disk-based uploads.
 *
 * <p>The context is created when a client provides a file hash for DDA validation. It stores the
 * generated salt and the decoded hash bytes so downstream verification can re-compute the digest
 * without re-deriving the salt. Instances are immutable and safe to pass between threads.
 *
 * <p>When no hash was supplied, callers use {@link #empty()} to get a shared instance with {@code
 * null} components. Downstream checks can call {@link #hasSalt()} to determine whether verification
 * should occur.
 */
final class DiskUploadContext {
  private final String salt;
  private final byte[] saltedHash;

  /**
   * Creates a new disk-upload context with optional salted hash data.
   *
   * @param salt per-request salt string used when computing the digest, or {@code null} when
   *     absent.
   * @param saltedHash hash bytes computed by the client, or {@code null} when not provided.
   */
  DiskUploadContext(String salt, byte[] saltedHash) {
    this.salt = salt;
    this.saltedHash = saltedHash;
  }

  /** Shared empty context used when no salted hash was supplied. */
  private static final DiskUploadContext EMPTY = new DiskUploadContext(null, null);

  String salt() {
    return salt;
  }

  byte[] saltedHash() {
    return saltedHash;
  }

  /**
   * Returns a shared empty context that indicates no salted hash is available.
   *
   * @return shared instance representing the absence of a salted hash.
   */
  static DiskUploadContext empty() {
    return EMPTY;
  }

  /**
   * Reports whether this context contains a salt and therefore expects hash verification.
   *
   * @return {@code true} when a salt is present and verification should proceed.
   */
  boolean hasSalt() {
    return salt != null;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof DiskUploadContext other)) return false;
    return Objects.equals(salt, other.salt) && Arrays.equals(saltedHash, other.saltedHash);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    int result = Objects.hash(salt);
    result = 31 * result + Arrays.hashCode(saltedHash);
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public @NotNull String toString() {
    return "DiskUploadContext[salt="
        + salt
        + ", saltedHash="
        + (saltedHash == null ? "null" : Arrays.toString(saltedHash))
        + ']';
  }
}
