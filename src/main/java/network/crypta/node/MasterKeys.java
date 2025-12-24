package network.crypta.node;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.support.Fields;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds the node's master secrets and manages persistence in {@code master.keys}.
 *
 * <p>The on-disk format (version 1) stores, in order:
 *
 * <ul>
 *   <li>{@code flags} (8 bytes, reserved for future use)
 *   <li>client cache key (32 bytes)
 *   <li>database key (32 bytes)
 *   <li>persistent tempfiles master secret (64 bytes)
 * </ul>
 *
 * The payload is encrypted using a key derived from the supplied password, a per-file salt, and
 * iterations of SHA-256. Integrity is verified with a truncated hash.
 *
 * <p>Instances are lightweight containers for decoded secrets. Backing arrays are mutable; callers
 * must not modify them unless they fully understand the ramifications. Use {@link #clear(byte[])}
 * to wipe arrays when no longer needed.
 */
public class MasterKeys {

  private static final Logger LOG = LoggerFactory.getLogger(MasterKeys.class);

  // Currently only the client cache uses this key for its legacy persistence.

  final byte[] clientCacheMasterKey;
  private final byte[] databaseKey;
  private final byte[] tempfilesMasterSecret;
  final long flags;

  // Reserved feature flags (none defined at present).

  /**
   * Constructs a new bundle of master secrets.
   *
   * <p>Inputs are stored by reference; they are not defensively copied here. Callers should clear
   * or replace their arrays if further mutation is undesired.
   *
   * @param clientCacheKey 32-byte key for the client cache; must not be {@code null}.
   * @param databaseKey 32-byte database key; must not be {@code null}.
   * @param tempfilesMasterSecret 64-byte secret for persistent encrypted tempfiles; must not be
   *     {@code null}.
   * @param flags reserved value for future format extensions.
   */
  public MasterKeys(
      byte[] clientCacheKey, byte[] databaseKey, byte[] tempfilesMasterSecret, long flags) {
    this.clientCacheMasterKey = clientCacheKey;
    this.databaseKey = databaseKey;
    this.flags = flags;
    this.tempfilesMasterSecret = tempfilesMasterSecret;
  }

  /**
   * Creates a new instance with randomly generated secrets.
   *
   * @param random randomness source; for production, supply a cryptographically strong RNG.
   * @return a new {@code MasterKeys} with 32-byte client cache and database keys and a 64-byte
   *     tempfiles master secret.
   */
  public static MasterKeys createRandom(Random random) {
    byte[] clientCacheKey = new byte[32];
    random.nextBytes(clientCacheKey);
    byte[] databaseKey = new byte[32];
    random.nextBytes(databaseKey);
    byte[] tempfilesMasterSecret = new byte[64];
    random.nextBytes(tempfilesMasterSecret);
    return new MasterKeys(clientCacheKey, databaseKey, tempfilesMasterSecret, 0);
  }

  static final int OLD_HASH_LENGTH = 4;
  static final int HASH_LENGTH = 12;

  static final int VERSION = 1;

  /** Upper bound to prevent pathological iteration counts. */
  static final long MAX_ITERATIONS = 1L << 40;

  /** Time budget in milliseconds for password-key derivation when a password is non-empty. */
  static int iterateTime = 1000;

  /**
   * Test-only hook to adjust the password derivation duration. Keeps unit tests fast and
   * deterministic without affecting production defaults.
   */
  @SuppressWarnings("SameParameterValue")
  static void setIterateTimeForTests(int millis) {
    iterateTime = millis;
  }

  /**
   * Reads or initializes the master keys from {@code master.keys}.
   *
   * <p>If a supported file exists, it is decrypted and parsed. If an old-format file is detected,
   * it is migrated in place to the current format. If the file is missing, a new one is generated
   * and written.
   *
   * @param masterKeysFile path to {@code master.keys}; must refer to a readable/writable file
   *     location.
   * @param hardRandom randomness source used for salts, IVs, and newly generated secrets.
   * @param password UTF-8 password used to derive the encryption key; may be empty to disable key
   *     stretching.
   * @return decoded secrets contained in the file, or newly generated values when the file does not
   *     exist.
   * @throws MasterKeysWrongPasswordException when decryption or integrity verification fails with
   *     the provided password.
   * @throws MasterKeysFileSizeException when the file length is outside expected bounds.
   * @throws IOException on I/O errors while reading or writing the file.
   */
  public static MasterKeys read(File masterKeysFile, Random hardRandom, String password)
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    LOG.info("Reading master.keys file");
    if (masterKeysFile != null && masterKeysFile.exists()) {
      long len = masterKeysFile.length();
      if (len > 1024) throw new MasterKeysFileSizeException(true);
      if (len < (32 + 32 + 8 + 32)) throw new MasterKeysFileSizeException(false);
      int length = (int) len;
      try (FileInputStream fis = new FileInputStream(masterKeysFile);
          DataInputStream dis = new DataInputStream(fis)) {
        if (len == 140) {
          MasterKeys ret = readOldFormat(dis, length, hardRandom, password);
          LOG.info("Old-format master.keys detected; writing new format");
          ret.changePassword(masterKeysFile, password, hardRandom);
          return ret;
        }
        return readNewFormat(dis, length, hardRandom, password, masterKeysFile);
      } catch (FileNotFoundException _) {
        // Ok, create a new one.
      } catch (EOFException _) {
        throw new MasterKeysFileSizeException(false);
      }
    }
    LOG.info("Creating new master.keys file");
    MasterKeys ret = createRandom(hardRandom);
    ret.write(masterKeysFile, password, hardRandom);
    return ret;
  }

  private static MasterKeys readNewFormat(
      DataInputStream dis, int length, Random hardRandom, String password, File masterKeysFile)
      throws IOException, MasterKeysWrongPasswordException {
    if (dis.readInt() != VERSION) throw new IOException("Bad version for master.keys");
    long iterations = dis.readLong();
    if (iterations < 0 || iterations > MAX_ITERATIONS)
      throw new IOException("Bad iterations " + iterations + " for master.keys");

    byte[] salt = new byte[32];
    dis.readFully(salt);
    byte[] iv = new byte[32];
    dis.readFully(iv);
    byte[] dataAndHash = new byte[length - salt.length - iv.length - 4 - 8];
    dis.readFully(dataAndHash);

    MessageDigest md = SHA256.getMessageDigest();
    byte[] outerKey = deriveOuterKey(password, salt, iterations, md);

    byte[] data = decryptAndVerify(dataAndHash, outerKey, iv, md);

    Decoded decoded = decodeV1Data(data, hardRandom);
    MasterKeys ret = decoded.keys();
    if (decoded.mustWrite()) {
      LOG.info("Create new master secret for encrypted tempfiles");
      ret.changePassword(masterKeysFile, password, hardRandom);
    }
    return ret;
  }

  private static byte[] deriveOuterKey(
      String password, byte[] salt, long iterations, MessageDigest md) {
    byte[] pwd = password.getBytes(StandardCharsets.UTF_8);
    md.update(pwd);
    md.update(salt);
    byte[] outerKey = md.digest();
    if (iterations > 0) {
      LOG.info("Deriving password key with {} iterations", iterations);
      for (long i = 0; i < iterations; i++) {
        md.update(salt);
        md.update(outerKey);
        outerKey = md.digest();
      }
    }
    return outerKey;
  }

  private static byte[] decryptAndVerify(
      byte[] dataAndHash, byte[] outerKey, byte[] iv, MessageDigest md)
      throws MasterKeysWrongPasswordException {
    BlockCipher cipher = newRijndael256();
    cipher.initialize(outerKey);
    PCFBMode pcfb = PCFBMode.create(cipher, iv);
    pcfb.blockDecipher(dataAndHash, 0, dataAndHash.length);
    byte[] data = Arrays.copyOf(dataAndHash, dataAndHash.length - HASH_LENGTH);
    byte[] hash = Arrays.copyOfRange(dataAndHash, data.length, dataAndHash.length);
    clear(dataAndHash);
    byte[] checkHash = md.digest(data);
    if (!Fields.byteArrayEqual(checkHash, hash, 0, 0, HASH_LENGTH)) {
      clear(data);
      clear(hash);
      throw new MasterKeysWrongPasswordException();
    }
    clear(hash);
    return data;
  }

  private static BlockCipher newRijndael256() {
    try {
      return new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      // Should never happen in supported environments; treat as unrecoverable configuration error.
      throw new IllegalStateException("AES-256 Rijndael cipher not available", e);
    }
  }

  private record Decoded(MasterKeys keys, boolean mustWrite) {}

  private static Decoded decodeV1Data(byte[] data, Random hardRandom) throws IOException {
    try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
        DataInputStream dataStream = new DataInputStream(bais)) {
      long flags = dataStream.readLong();
      byte[] clientCacheKey = new byte[32];
      dataStream.readFully(clientCacheKey);
      byte[] databaseKey = new byte[32];
      dataStream.readFully(databaseKey);
      byte[] tempfilesMasterSecret = new byte[64];
      boolean mustWrite = false;
      if (data.length >= 8 + 32 + 32 + 64) {
        dataStream.readFully(tempfilesMasterSecret);
      } else {
        hardRandom.nextBytes(tempfilesMasterSecret);
        mustWrite = true;
      }
      MasterKeys ret = new MasterKeys(clientCacheKey, databaseKey, tempfilesMasterSecret, flags);
      clear(data);
      return new Decoded(ret, mustWrite);
    }
  }

  private static MasterKeys readOldFormat(
      DataInputStream dis, int length, Random hardRandom, String password)
      throws IOException, MasterKeysWrongPasswordException {
    byte[] salt = new byte[32];
    dis.readFully(salt);
    byte[] iv = new byte[32];
    dis.readFully(iv);
    byte[] dataAndHash = new byte[length - salt.length - iv.length];
    dis.readFully(dataAndHash);
    byte[] pwd = password.getBytes(StandardCharsets.UTF_8);
    MessageDigest md = SHA256.getMessageDigest();
    md.update(pwd);
    md.update(salt);
    byte[] outerKey = md.digest();
    BlockCipher cipher = newRijndael256();
    cipher.initialize(outerKey);
    PCFBMode pcfb = PCFBMode.create(cipher, iv);
    pcfb.blockDecipher(dataAndHash, 0, dataAndHash.length);
    byte[] data = Arrays.copyOf(dataAndHash, dataAndHash.length - OLD_HASH_LENGTH);
    byte[] hash = Arrays.copyOfRange(dataAndHash, data.length, dataAndHash.length);
    clear(dataAndHash);
    byte[] checkHash = md.digest(data);
    if (!Fields.byteArrayEqual(checkHash, hash, 0, 0, OLD_HASH_LENGTH)) {
      clear(data);
      clear(hash);
      throw new MasterKeysWrongPasswordException();
    }

    // Integrity check passed; decode the legacy payload.
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    dis = new DataInputStream(bais);
    byte[] flagsBytes = new byte[8];
    dis.readFully(flagsBytes);
    long flags = Fields.bytesToLong(flagsBytes);
    // Flags are reserved. Future formats may indicate which subsystems are encrypted.
    byte[] clientCacheKey = new byte[32];
    dis.readFully(clientCacheKey);
    byte[] databaseKey = new byte[32];
    dis.readFully(databaseKey);
    byte[] tempfilesMasterSecret = new byte[64];
    LOG.info("Create new master secret for encrypted tempfiles");
    hardRandom.nextBytes(tempfilesMasterSecret);
    MasterKeys ret = new MasterKeys(clientCacheKey, databaseKey, tempfilesMasterSecret, flags);
    clear(data);
    clear(hash);
    return ret;
  }

  /**
   * Overwrites the provided byte array with zeros.
   *
   * @param buf target buffer; may be {@code null} for a no-op.
   */
  public static void clear(byte[] buf) {
    if (buf == null) return; // Valid no-op, simplifies code
    Arrays.fill(buf, (byte) 0x00);
  }

  /**
   * Re-encrypts and writes {@code master.keys} with a new password.
   *
   * <p>Uses fresh salt and IV. The file is rewritten in place and synced.
   *
   * @param masterKeysFile destination file; must be writable.
   * @param newPassword UTF-8 password; may be empty to store with minimal derivation.
   * @param hardRandom randomness source for salt/IV.
   * @throws IOException on I/O failures.
   */
  public void changePassword(File masterKeysFile, String newPassword, Random hardRandom)
      throws IOException {
    LOG.info("Writing master.keys file");
    write(masterKeysFile, newPassword, hardRandom);
  }

  private void write(File masterKeysFile, String newPassword, Random hardRandom)
      throws IOException {
    // Assemble the encrypted blob in memory, then replace the file contents.

    // New IV and salt; payload carries existing keys and flags.

    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    byte[] iv = new byte[32];
    hardRandom.nextBytes(iv);
    byte[] salt = new byte[32];
    hardRandom.nextBytes(salt);

    byte[] pwd = newPassword.getBytes(StandardCharsets.UTF_8);
    MessageDigest md = SHA256.getMessageDigest();
    md.update(pwd);
    md.update(salt);
    byte[] outerKey = md.digest();
    long iterations = 0;
    if (!newPassword.isEmpty()) {
      long startTime = System.currentTimeMillis();
      while (System.currentTimeMillis() < startTime + iterateTime
          && iterations < MAX_ITERATIONS - 20) {
        for (int i = 0; i < 10; i++) {
          iterations++;
          md.update(salt);
          md.update(outerKey);
          outerKey = md.digest();
        }
      }
      LOG.info("Derived password key with {} iterations.", iterations);
    }

    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeInt(VERSION);
    dos.writeLong(iterations);
    baos.write(salt);
    baos.write(iv);
    int hashedStart = salt.length + iv.length + 4 + 8;
    dos.writeLong(flags);
    baos.write(clientCacheMasterKey);
    baos.write(databaseKey);
    baos.write(tempfilesMasterSecret);

    byte[] data = baos.toByteArray();

    md.update(data, hashedStart, data.length - hashedStart);
    byte[] hash = md.digest();
    baos.write(hash, 0, HASH_LENGTH);
    data = baos.toByteArray();

    BlockCipher cipher = newRijndael256();
    cipher.initialize(outerKey);
    PCFBMode pcfb = PCFBMode.create(cipher, iv);
    pcfb.blockEncipher(data, hashedStart, data.length - hashedStart);

    try (RandomAccessFile raf = new RandomAccessFile(masterKeysFile, "rw")) {
      raf.seek(0);
      raf.write(data);
      long len = raf.length();
      if (len > data.length) {
        byte[] diff = new byte[(int) (len - data.length)];
        raf.write(diff);
        raf.setLength(data.length);
      }
      raf.getFD().sync();
    }
  }

  public static void killMasterKeys(File masterKeysFile) throws IOException {
    FileUtil.secureDelete(masterKeysFile);
  }

  /**
   * Returns a database key wrapper for deriving component-specific keys.
   *
   * <p>The returned {@link DatabaseKey} defends against external mutation by copying the secret
   * internally.
   *
   * @return a new {@link DatabaseKey} based on the stored database key.
   */
  public DatabaseKey createDatabaseKey() {
    return new DatabaseKey(databaseKey);
  }

  /**
   * Returns the master secret used to derive keys for persistent encrypted tempfiles.
   *
   * <p>The returned {@link MasterSecret} receives a clone of the underlying bytes so subsequent
   * mutations by the caller do not affect this instance.
   *
   * @return a {@link MasterSecret} for tempfiles encryption.
   */
  public MasterSecret getPersistentMasterSecret() {
    return new MasterSecret(tempfilesMasterSecret.clone());
  }
}
