package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.crypt.SHA256;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucketFactory;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({
  "java:S100",
  "java:S2245"
}) // Naming rule; PRNG in tests is deterministic and safe
@ExtendWith(MockitoExtension.class)
class MetadataTest {

  private static final String FILE_LOGO = "logo.png";
  private static final String FILE_INDEX = "index.html";
  private static final String DIR_ASSETS = "assets";
  private static final String MIME_TEXT = "text/plain";

  @Test
  void getCryptoKey_whenSha256HashPresent_returnsDerivedKey() {
    byte[] sha = new byte[32];
    for (int i = 0; i < sha.length; i++) sha[i] = (byte) (i * 7 + 3);
    HashResult[] hashes = new HashResult[] {new HashResult(HashType.SHA256, sha)};

    // Expected derivation = SHA256(sha || "SPLITKEY")
    MessageDigest md = SHA256.getMessageDigest();
    md.update(sha);
    md.update("SPLITKEY".getBytes(StandardCharsets.UTF_8));
    byte[] expected = md.digest();

    byte[] actual = Metadata.getCryptoKey(hashes);
    assertArrayEquals(expected, actual);
  }

  @Test
  void getCryptoKey_whenByteArrayProvided_returnsDerivedKey() {
    byte[] sha = new byte[32];
    for (int i = 0; i < sha.length; i++) sha[i] = (byte) (255 - i);

    MessageDigest md = SHA256.getMessageDigest();
    md.update(sha);
    md.update("SPLITKEY".getBytes(StandardCharsets.UTF_8));
    byte[] expected = md.digest();

    byte[] actual = Metadata.getCryptoKey(sha);
    assertArrayEquals(expected, actual);
  }

  @Test
  void getCryptoKey_whenMissingSha256_throwsIllegalArgumentException() {
    HashResult[] hashes = new HashResult[] {new HashResult(HashType.SHA1, new byte[20])};
    assertThrows(IllegalArgumentException.class, () -> Metadata.getCryptoKey(hashes));
    assertThrows(IllegalArgumentException.class, () -> Metadata.getCryptoKey((HashResult[]) null));
    assertThrows(IllegalArgumentException.class, () -> Metadata.getCryptoKey(new HashResult[0]));
  }

  @Test
  void getCrossSegmentSeed_whenThisLayerProvided_usesThisLayerOnly() {
    byte[] layerHash = new byte[32];
    for (int i = 0; i < layerHash.length; i++) layerHash[i] = (byte) i;
    // hashes should be ignored when hashThisLayerOnly is provided
    HashResult[] hashes = new HashResult[] {new HashResult(HashType.SHA256, new byte[32])};

    MessageDigest md = SHA256.getMessageDigest();
    md.update(layerHash);
    md.update("CROSS_SEGMENT_SEED".getBytes(StandardCharsets.UTF_8));
    byte[] expected = md.digest();

    byte[] actual = Metadata.getCrossSegmentSeed(hashes, layerHash);
    assertArrayEquals(expected, actual);
  }

  @Test
  void getCrossSegmentSeed_whenOnlyHashesProvided_usesSha256FromHashes() {
    byte[] sha = new byte[32];
    for (int i = 0; i < sha.length; i++) sha[i] = (byte) (i * 5 + 11);
    HashResult[] hashes = new HashResult[] {new HashResult(HashType.SHA256, sha)};

    MessageDigest md = SHA256.getMessageDigest();
    md.update(sha);
    md.update("CROSS_SEGMENT_SEED".getBytes(StandardCharsets.UTF_8));
    byte[] expected = md.digest();

    byte[] actual = Metadata.getCrossSegmentSeed(hashes, null);
    assertArrayEquals(expected, actual);
  }

  @Test
  void getCrossSegmentSeed_whenMissingSha256_throwsIllegalArgumentException() {
    HashResult[] hashes = new HashResult[] {new HashResult(HashType.SHA1, new byte[20])};
    assertThrows(IllegalArgumentException.class, () -> Metadata.getCrossSegmentSeed(hashes, null));
  }

  @Test
  void mkRedirectionManifest_simpleAndNested_roundTripAndAccessors() throws Exception {
    Random rnd = new Random(1234L);
    FreenetURI chkDefault = FreenetURI.generateRandomCHK(rnd);
    FreenetURI chkIndex = FreenetURI.generateRandomCHK(rnd);
    FreenetURI chkLogo = FreenetURI.generateRandomCHK(rnd);

    HashMap<String, Object> subdir = new HashMap<>();
    subdir.put(FILE_LOGO, chkLogo.toString());

    HashMap<String, Object> dir = new HashMap<>();
    dir.put("", chkDefault.toString());
    dir.put(FILE_INDEX, chkIndex.toString());
    dir.put(DIR_ASSETS, subdir);

    Metadata manifest = Metadata.mkRedirectionManifest(dir);
    assertTrue(manifest.isSimpleManifest());
    assertFalse(manifest.haveFlags()); // SIMPLE_MANIFEST uses no flags
    assertEquals(2, manifest.getDocuments().size()); // excludes the default doc ("")

    // Access specific entries
    assertTrue(manifest.getDefaultDocument().isSingleFileRedirect());
    assertEquals(chkDefault, manifest.getDefaultDocument().getSingleTarget());
    assertEquals(chkIndex, manifest.getDocument(FILE_INDEX).getSingleTarget());

    Metadata assets = manifest.getDocument(DIR_ASSETS);
    assertNotNull(assets);
    assertTrue(assets.isSimpleManifest());
    assertEquals(chkLogo, assets.getDocument(FILE_LOGO).getSingleTarget());

    // Round-trip through binary
    byte[] bytes = manifest.writeToByteArray();
    Metadata parsed = Metadata.construct(bytes);
    assertTrue(parsed.isSimpleManifest());
    assertEquals(chkDefault, parsed.getDefaultDocument().getSingleTarget());
    assertEquals(chkIndex, parsed.getDocument(FILE_INDEX).getSingleTarget());
    assertEquals(chkLogo, parsed.getDocument(DIR_ASSETS).getDocument(FILE_LOGO).getSingleTarget());
  }

  @Test
  void mkRedirectionManifestWithMetadata_whenSlashInKey_throws() {
    HashMap<String, Object> bad = new HashMap<>();
    // The value type here must be either Metadata or HashMap; provide a valid leaf Metadata
    bad.put(
        "a/b",
        new Metadata(
            DocumentType.SIMPLE_REDIRECT,
            null,
            null,
            FreenetURI.generateRandomCHK(new Random(1L)),
            null));
    assertThrows(
        IllegalArgumentException.class, () -> Metadata.mkRedirectionManifestWithMetadata(bad));
  }

  @Test
  void simpleRedirect_writeAndConstruct_roundTripSingleTarget() throws Exception {
    FreenetURI uri = FreenetURI.generateRandomCHK(new Random(0x09080706L));
    ClientMetadata cm = new ClientMetadata(MIME_TEXT);
    Metadata md = new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, uri, cm);
    assertTrue(md.haveFlags());
    assertTrue(md.isSingleFileRedirect());
    assertEquals(uri, md.getSingleTarget());

    byte[] bytes = md.writeToByteArray();
    Metadata parsed = Metadata.construct(bytes);
    assertTrue(parsed.isSingleFileRedirect());
    assertEquals(uri, parsed.getSingleTarget());
  }

  @Test
  void writeLength_matchesWrittenBytesLength() throws Exception {
    FreenetURI uri = FreenetURI.generateRandomCHK(new Random(42L));
    Metadata md =
        new Metadata(
            DocumentType.SIMPLE_REDIRECT, null, null, uri, new ClientMetadata("application/json"));
    long len = md.writtenLength();
    assertEquals(len, md.writeToByteArray().length);
  }

  @Test
  void toBucket_writesReadOnlyBucket_withSameBytes() throws Exception {
    FreenetURI uri = FreenetURI.generateRandomCHK(new Random(77L));
    Metadata md =
        new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, uri, new ClientMetadata(MIME_TEXT));
    byte[] expected = md.writeToByteArray();

    try (RandomAccessBucket bucket = md.toBucket(new ArrayBucketFactory());
        DataInputStream dis = new DataInputStream(bucket.getInputStream())) {
      assertTrue(bucket.isReadOnly());
      byte[] buf = dis.readAllBytes();
      assertArrayEquals(expected, buf);
    }
  }

  @Test
  void haveFlags_variesByDocumentType() {
    Metadata manifestWithMeta = Metadata.mkRedirectionManifestWithMetadata(new HashMap<>());
    assertFalse(manifestWithMeta.haveFlags()); // SIMPLE_MANIFEST

    Metadata shortlink = new Metadata(DocumentType.SYMBOLIC_SHORTLINK, null, null, "target", null);
    assertTrue(shortlink.haveFlags());
  }

  @Test
  void archiveInternalRedirect_stripsLeadingSlashes_andRejectsEmpty() {
    // Leading slashes are stripped
    Metadata md =
        new Metadata(
            DocumentType.ARCHIVE_INTERNAL_REDIRECT,
            null,
            null,
            "/dir/file.txt",
            new ClientMetadata(MIME_TEXT));
    assertEquals("dir/file.txt", md.getArchiveInternalName());

    // Empty target name rejected
    ClientMetadata emptyTargetMeta = new ClientMetadata(MIME_TEXT);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new Metadata(DocumentType.ARCHIVE_INTERNAL_REDIRECT, null, null, "", emptyTargetMeta));
  }

  @Test
  void getArchiveInternalName_whenWrongType_throws() {
    FreenetURI uri = FreenetURI.generateRandomCHK(new Random(0x00050607L));
    Metadata md =
        new Metadata(DocumentType.SIMPLE_REDIRECT, null, null, uri, new ClientMetadata(MIME_TEXT));
    assertThrows(IllegalArgumentException.class, md::getArchiveInternalName);
  }

  @Test
  void forceMap_behavior_copiesOrCasts_andRejectsBadKeysOrTypes() {
    HashMap<String, Object> original = new HashMap<>();
    original.put("x", "y");
    // Returns the same instance for HashMap
    Map<String, Object> same = Metadata.forceMap(original);
    assertSame(original, same);

    Map<String, Object> mapOf = Map.of("a", 1, "b", 2);
    Map<String, Object> copy = Metadata.forceMap(mapOf);
    assertEquals(2, copy.size());
    assertEquals(1, copy.get("a"));
    assertEquals(2, copy.get("b"));

    HashMap<Object, Object> badKeyMap = new HashMap<>();
    badKeyMap.put(123, "v");
    Map<String, Object> cast = Metadata.forceMap(badKeyMap);
    assertSame(cast, badKeyMap);
    assertThrows(ClassCastException.class, () -> Metadata.forceMap("not a map"));
  }

  @Test
  void guessCompatibilityMode_usesTopOrFallsBackToMax() throws Exception {
    // Build a SIMPLE_REDIRECT with non-zero top fields but COMPAT_UNKNOWN in the header.
    FreenetURI uri = FreenetURI.generateRandomCHK(new Random(0x0A141E28L));
    byte[] bytes = topHeaderUnknownBytes(uri);

    // Parse the bytes back. For CHK with AES-CTR, maxCompatMode becomes the latest compatibility.
    Metadata parsed = Metadata.construct(bytes);
    assertTrue(parsed.hasTopData());
    assertEquals(1, parsed.getParsedVersion());
    assertEquals(CompatibilityMode.COMPAT_UNKNOWN, parsed.getTopCompatibilityMode());
    assertEquals(CompatibilityMode.latest(), parsed.getMaxCompatMode());
    assertEquals(CompatibilityMode.latest(), parsed.guessCompatibilityMode());
  }

  @Test
  void isValidSplitfileCryptoAlgorithm_variousValues() {
    assertTrue(Metadata.isValidSplitfileCryptoAlgorithm((byte) 0)); // legacy sentinel
    assertTrue(Metadata.isValidSplitfileCryptoAlgorithm(Key.ALGO_AES_PCFB_256_SHA256));
    assertTrue(Metadata.isValidSplitfileCryptoAlgorithm(Key.ALGO_AES_CTR_256_SHA256));
    assertFalse(Metadata.isValidSplitfileCryptoAlgorithm((byte) 0x7F));
  }

  // Helper used to keep the exception site explicit and the test concise.
  private static byte[] topHeaderUnknownBytes(FreenetURI uri) throws Exception {
    Metadata writer =
        new Metadata(
            new MetadataRedirectTarget(
                DocumentType.SIMPLE_REDIRECT, null, null, uri, new ClientMetadata(MIME_TEXT)),
            new MetadataTopLayerInfo(
                new TopLayerBlockInfo(
                    1234L, // topSize
                    1200L, // topCompressedSize
                    10, // topBlocksRequired
                    12, // topBlocksTotal
                    false,
                    CompatibilityMode
                        .COMPAT_UNKNOWN), // write unknown into the header alongside non-zero fields
                new TopLayerHashInfo(null, null)));
    return writer.writeToByteArray();
  }

  @Test
  void splitfileConstructor_whenVersion0_disallowsV1Fields() {
    // For coverage of constructor preconditions: when topCompatibilityMode < COMPAT_1255,
    // parsedVersion becomes 0 and v1-only inputs like splitfileCryptoKey must be null.
    // Minimal splitfile arrays (not used further in this test)
    var data = new ClientCHK[] {};
    var check = new ClientCHK[] {};
    ClientMetadata cm = new ClientMetadata("application/octet-stream");
    SplitfileParams params =
        new SplitfileParams(
            SplitfileAlgorithm.NONREDUNDANT,
            data,
            check,
            1,
            0,
            0,
            0,
            Key.ALGO_AES_PCFB_256_SHA256,
            // splitfileCryptoKey must be null for version 0; pass non-null to trigger exception
            new byte[32],
            false);
    SplitfilePayload payload = new SplitfilePayload(cm, 1L, null, null, 1L, false);
    MetadataTopLayerInfo topLayer =
        new MetadataTopLayerInfo(
            new TopLayerBlockInfo(
                0L, 0L, 0, 0, false, CompatibilityMode.COMPAT_1250), // < 1255 → parsedVersion 0
            new TopLayerHashInfo(null, null));

    assertThrows(IllegalArgumentException.class, () -> new Metadata(params, payload, topLayer));
  }

  @Test
  void splitfileWithoutTopBlocks_preservesV1_andWritesCryptoParams() {
    // Arrange: one minimal data key, no check keys, no top hashes/blocks.
    SecureRandom rng = new SecureRandom();
    byte[] routingKey = new byte[NodeCHK.KEY_LENGTH];
    rng.nextBytes(routingKey);
    byte[] splitKey = new byte[ClientCHK.CRYPTO_KEY_LENGTH];
    rng.nextBytes(splitKey);
    ClientCHK dataKey =
        new ClientCHK(routingKey, splitKey, false, Key.ALGO_AES_CTR_256_SHA256, (short) -1);
    Metadata meta = getMetadata(dataKey, splitKey);

    // Assert: the version remains 1 and crypto parameters are preserved.
    assertEquals(1, meta.getParsedVersion(), "parsedVersion should be 1");
    assertEquals(
        Key.ALGO_AES_CTR_256_SHA256,
        meta.getSplitfileCryptoAlgorithm(),
        "Splitfile crypto algorithm must be preserved");
    assertArrayEquals(
        splitKey, meta.getSplitfileCryptoKey(), "Splitfile single crypto key must be preserved");
  }

  private static @NotNull Metadata getMetadata(ClientCHK dataKey, byte[] splitKey) {
    ClientCHK[] dataURIs = new ClientCHK[] {dataKey};
    ClientCHK[] checkURIs = new ClientCHK[] {};

    // Act: build a splitfile with compat >= 1255 (requires metadata v1) but no top section.
    return new Metadata(
        new SplitfileParams(
            SplitfileAlgorithm.NONREDUNDANT,
            dataURIs,
            checkURIs,
            /* segmentSize= */ 1,
            /* checkSegmentSize= */ 0,
            /* deductBlocksFromSegments= */ 0,
            /* crossSegmentBlocks= */ 0,
            /* splitfileCryptoAlgorithm= */ Key.ALGO_AES_CTR_256_SHA256,
            /* splitfileCryptoKey= */ splitKey,
            /* specifySplitfileKey= */ true),
        new SplitfilePayload(
            /* clientMetadata= */ null,
            /* dataLength= */ 1024L,
            /* archiveType= */ null,
            /* compressionCodec= */ null,
            /* decompressedLength= */ 0L,
            /* isMetadata= */ false),
        new MetadataTopLayerInfo(
            new TopLayerBlockInfo(
                /* size= */ 0L,
                /* compressedSize= */ 0L,
                /* blocksRequired= */ 0,
                /* blocksTotal= */ 0,
                /* dontCompress= */ false,
                /* compatMode= */ CompatibilityMode.COMPAT_1255),
            new TopLayerHashInfo(/* hashes= */ null, /* hashThisLayerOnly= */ null)));
  }
}
