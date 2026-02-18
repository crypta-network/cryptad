package network.crypta.crypt;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptByteBufferTest {
  private static final CryptByteBufferType[] cipherTypes = CryptByteBufferType.values();

  private static final String IV_PLAIN_TEXT =
      "6bc1bee22e409f96e93d7e117393172a"
          + "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef"
          + "f69f2445df4f9b17ad2b417be66c3710";

  private static final String[] plainText = {
    // AESCTR, CHACHA_128, CHACHA_256
    IV_PLAIN_TEXT, IV_PLAIN_TEXT, IV_PLAIN_TEXT
  };

  private static final byte[][] keys = {
    // AESCTR
    Hex.decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
    // CHACHA_128
    Hex.decode("8c123cffb0297a71ae8388109a6527dd"),
    // CHACHA_256
    Hex.decode("a63add96a3d5975e2dad2f904ff584a32920e8aa54263254161362d1fb785790")
  };
  private static final byte[][] ivs = {
    // AESCTR (16 bytes)
    Hex.decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
    // CHACHA_128 (8 bytes)
    Hex.decode("73c3c8df749084bb"),
    // CHACHA_256 (8 bytes)
    Hex.decode("7b471cf26ee479fb")
  };

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  // --- Additional deterministic edge-case tests (JUnit 6) ---

  @Test
  void constructor_whenKeyLengthWrong_expectIllegalArgumentException() {
    // Arrange
    byte[] wrongKey = new byte[31]; // AESCTR requires 32 bytes
    Arrays.fill(wrongKey, (byte) 0xAB);
    byte[] wrongKeyChaCha = new byte[63]; // ChaCha256 requires 64 bytes
    Arrays.fill(wrongKeyChaCha, (byte) 0xCD);

    // Act & Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> new CryptByteBuffer(CryptByteBufferType.AESCTR, wrongKey));
    assertThrows(
        IllegalArgumentException.class,
        () -> new CryptByteBuffer(CryptByteBufferType.CHACHA_256, wrongKeyChaCha));
  }

  @Test
  void encrypt_whenOutputTooSmall_expectIllegalArgumentException() throws GeneralSecurityException {
    // Arrange
    CryptByteBufferType type = CryptByteBufferType.CHACHA_128;
    CryptByteBuffer crypt = new CryptByteBuffer(type, keys[1], ivs[1]);
    byte[] input = Hex.decode(IV_PLAIN_TEXT);
    byte[] output = new byte[input.length - 1]; // too small by 1 byte

    // Act & Assert
    assertThrows(
        IllegalArgumentException.class, () -> crypt.encrypt(input, 0, input.length, output, 0));
  }

  @Test
  void decrypt_whenOutputTooSmall_expectIllegalArgumentException() throws GeneralSecurityException {
    // Arrange
    CryptByteBufferType type = CryptByteBufferType.CHACHA_128;
    CryptByteBuffer crypt = new CryptByteBuffer(type, keys[1], ivs[1]);
    byte[] plain = Hex.decode(IV_PLAIN_TEXT);
    byte[] cipher = crypt.encryptCopy(plain);
    byte[] tooSmall = new byte[cipher.length - 2];

    // Act & Assert
    assertThrows(
        IllegalArgumentException.class, () -> crypt.decrypt(cipher, 0, cipher.length, tooSmall, 0));
  }

  @Test
  void encryptByteBuffer_whenOutputSmallerThanInput_processesOnlyMinAndAdvancesPositions()
      throws GeneralSecurityException {
    // Arrange
    CryptByteBufferType type = CryptByteBufferType.AESCTR;
    CryptByteBuffer crypt = new CryptByteBuffer(type, keys[0], ivs[0]);
    byte[] plain = Hex.decode(IV_PLAIN_TEXT);
    ByteBuffer in = ByteBuffer.wrap(plain);
    int outLen = plain.length / 3; // deliberately smaller
    ByteBuffer out = ByteBuffer.allocate(outLen);
    byte[] ref = new CryptByteBuffer(type, keys[0], ivs[0]).encryptCopy(plain, 0, outLen);

    // Act
    crypt.encrypt(in, out);

    // Assert (positions and bytes)
    assertEquals(outLen, in.position());
    assertEquals(outLen, out.position());
    out.flip();
    byte[] got = new byte[out.remaining()];
    out.get(got);
    assertArrayEquals(ref, got);
  }

  @Test
  void encryptCopyByteBuffer_returnsArrayBackedWithZeroOffsetAndZeroPosition()
      throws GeneralSecurityException {
    // Arrange
    CryptByteBuffer crypt = new CryptByteBuffer(CryptByteBufferType.CHACHA_256, keys[2], ivs[2]);
    ByteBuffer input = ByteBuffer.allocateDirect(16);
    input.put(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
    input.flip();

    // Act
    ByteBuffer out = crypt.encryptCopy(input);

    // Assert (buffer characteristics)
    assertEquals(16, out.capacity());
    assertEquals(16, out.remaining());
    assertEquals(0, out.position());
    assertFalse(out.isDirect());
    assert out.hasArray();
    assertEquals(0, out.arrayOffset());

    // Act (decrypt)
    ByteBuffer dec = crypt.decryptCopy(out);

    // Assert (round-trip)
    assertEquals(0, dec.position());
    byte[] back = new byte[16];
    dec.get(back);
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, back);
  }

  @Test
  void constructor_withByteArrayIvAndOffset_extractsCorrectSlice() throws GeneralSecurityException {
    // Arrange
    CryptByteBufferType type = CryptByteBufferType.CHACHA_128; // iv size = 8 bytes
    byte[] key = keys[1];
    byte[] ivPadded =
        new byte[] {
          99,
          98,
          97, // prefix garbage
          0x73,
          (byte) 0xC3,
          (byte) 0xC8,
          (byte) 0xDF,
          0x74,
          (byte) 0x90,
          (byte) 0x84,
          (byte) 0xBB,
          // equals ivs[1]
          1,
          2,
          3
        }; // suffix garbage
    int offset = 3;
    // Act
    CryptByteBuffer crypt = new CryptByteBuffer(type, key, ivPadded, offset);

    // Assert
    assertArrayEquals(ivs[1], crypt.getIV().getIV());
  }

  @Test
  void setIV_whenChanged_changesCiphertextAndRoundTrips() throws GeneralSecurityException {
    // Arrange
    CryptByteBufferType type = CryptByteBufferType.AESCTR;
    byte[] plain = Hex.decode(IV_PLAIN_TEXT);
    CryptByteBuffer crypt = new CryptByteBuffer(type, keys[0], ivs[0]);
    byte[] c1 = crypt.encryptCopy(plain);

    // Change IV to a different fixed value
    IvParameterSpec iv2 =
        new IvParameterSpec(
            new byte[] {
              // 16 bytes
              (byte) 0xFF,
              (byte) 0xEE,
              (byte) 0xDD,
              (byte) 0xCC,
              (byte) 0xBB,
              (byte) 0xAA,
              0x11,
              0x22,
              0x33,
              0x44,
              0x55,
              0x66,
              0x00,
              0x01,
              0x02,
              0x03
            });
    // Act (change IV and re-encrypt)
    crypt.setIV(iv2);
    byte[] c2 = crypt.encryptCopy(plain);

    // Assert (IV applied and ciphertext changed)
    assertArrayEquals(iv2.getIV(), crypt.getIV().getIV());
    assertFalse(Arrays.equals(c1, c2));

    // Act (decrypt with new IV)
    byte[] p2 = crypt.decryptCopy(c2);

    // Assert (round-trip)
    assertArrayEquals(plain, p2);

    // Act (reset IV and encrypt again)
    crypt.setIV(new IvParameterSpec(ivs[0]));
    byte[] c3 = crypt.encryptCopy(plain);

    // Assert (matches original ciphertext)
    assertArrayEquals(c1, c3);
  }

  @Test
  void encryptDecrypt_whenByteArrayRoundTrip_expectOriginalPlaintext()
      throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] plaintext = Hex.decode(plainText[i]);

      // Act
      byte[] ciphertext = crypt.encryptCopy(plaintext);
      byte[] decrypted = crypt.decryptCopy(ciphertext);

      // Assert
      assertArrayEquals(plaintext, decrypted, "CryptByteBufferType: " + type.name());
    }
  }

  @Test
  void encryptDecrypt_whenOneByteAtATime_expectBulkEquivalence() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt1;
      CryptByteBuffer crypt2;

      if (!type.isStreamCipher) continue;

      if (ivs[i] == null) {
        crypt1 = new CryptByteBuffer(type, keys[i]);
        crypt2 = new CryptByteBuffer(type, keys[i]);
      } else {
        crypt1 = new CryptByteBuffer(type, keys[i], ivs[i]);
        crypt2 = new CryptByteBuffer(type, keys[i], ivs[i]);
      }

      // Arrange
      byte[] origPlaintext = Hex.decode(plainText[i]);
      byte[] bulkCiphertext = crypt1.encryptCopy(origPlaintext);
      byte[] streamingBuf = origPlaintext.clone();

      // Act (encrypt one byte at a time)
      for (int j = 0; j < streamingBuf.length; j++) {
        crypt2.encrypt(streamingBuf, j, 1);
      }

      // Assert (ciphertexts match)
      assertArrayEquals(bulkCiphertext, streamingBuf);

      // Act (decrypt one byte at a time)
      for (int j = 0; j < streamingBuf.length; j++) {
        crypt2.decrypt(streamingBuf, j, 1);
      }

      // Assert (round-trip equals original)
      assertArrayEquals(origPlaintext, streamingBuf);
    }
  }

  @Test
  void encryptDecrypt_whenRandomChunkSizes_expectBulkEquivalence() throws GeneralSecurityException {
    Random random = new Random(0xAAAAAAAAL);
    for (int i = 0; i < cipherTypes.length; i++) {
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt1;
      CryptByteBuffer crypt2;

      if (!type.isStreamCipher) continue;

      if (ivs[i] == null) {
        crypt1 = new CryptByteBuffer(type, keys[i]);
        crypt2 = new CryptByteBuffer(type, keys[i]);
      } else {
        crypt1 = new CryptByteBuffer(type, keys[i], ivs[i]);
        crypt2 = new CryptByteBuffer(type, keys[i], ivs[i]);
      }

      // Arrange
      byte[] origPlaintext = Hex.decode(plainText[i]);
      byte[] bulkCiphertext = crypt1.encryptCopy(origPlaintext);
      byte[] streamingBuf = origPlaintext.clone();

      // Act (encrypt variable chunk sizes)
      int j = 0;
      while (j < streamingBuf.length) {
        int r = streamingBuf.length - j;
        int copy = 1 + (r == 1 ? 0 : random.nextInt(r - 1));
        crypt2.encrypt(streamingBuf, j, copy);
        j += copy;
      }

      // Assert (ciphertexts match)
      assertArrayEquals(streamingBuf, bulkCiphertext);

      // Act (decrypt variable chunk sizes)
      j = 0;
      while (j < streamingBuf.length) {
        int r = streamingBuf.length - j;
        int copy = 1 + (r == 1 ? 0 : random.nextInt(r - 1));
        crypt2.decrypt(streamingBuf, j, copy);
        j += copy;
      }

      // Assert (round-trip equals original)
      assertArrayEquals(streamingBuf, origPlaintext);
    }
  }

  @Test
  void encryptDecrypt_whenInPlace_expectOriginalPlaintext() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] buffer = Hex.decode(plainText[i]);
      byte[] original = buffer.clone();

      // Act (encrypt in place)
      crypt.encrypt(buffer, 0, buffer.length);

      // Assert (ciphertext differs from original)
      assertThat(buffer, not(equalTo(original)));

      // Act (decrypt in place)
      crypt.decrypt(buffer, 0, buffer.length);

      // Assert (round-trip equals original)
      assertThat("CryptByteBufferType: " + type.name(), original, equalTo(buffer));
    }
  }

  @Test
  void encryptDecrypt_whenInPlaceWithOffsets_expectOriginalPlaintext()
      throws GeneralSecurityException {
    int header = 5;
    int footer = 5;
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] originalPlaintext = Hex.decode(plainText[i]);
      byte[] buffer = new byte[header + originalPlaintext.length + footer];
      System.arraycopy(originalPlaintext, 0, buffer, header, originalPlaintext.length);
      byte[] before = buffer.clone();

      // Act (encrypt range in place)
      crypt.encrypt(buffer, footer, originalPlaintext.length);

      // Assert (buffer changed)
      assertThat(buffer, not(equalTo(before)));

      // Act (decrypt range in place)
      crypt.decrypt(buffer, footer, originalPlaintext.length);

      // Assert (round-trip equals original slice)
      assertArrayEquals(
          originalPlaintext,
          Arrays.copyOfRange(buffer, footer, footer + originalPlaintext.length),
          "CryptByteBufferType: " + type.name());
    }
  }

  @Test
  void encryptDecrypt_whenOutOfPlaceWithOffsets_expectOriginalPlaintext()
      throws GeneralSecurityException {
    int inHeader = 5;
    int inFooter = 5;
    int outHeader = 33;
    int outFooter = 33;
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] originalPlaintext = Hex.decode(plainText[i]);
      byte[] inBuffer = new byte[inHeader + originalPlaintext.length + inFooter];
      System.arraycopy(originalPlaintext, 0, inBuffer, inHeader, originalPlaintext.length);
      byte[] inBefore = inBuffer.clone();
      byte[] outBuffer = new byte[outHeader + originalPlaintext.length + outFooter];
      byte[] outBefore = outBuffer.clone();

      // Act (encrypt out-of-place)
      crypt.encrypt(inBuffer, inFooter, originalPlaintext.length, outBuffer, outHeader);

      // Assert (input unchanged, output changed)
      assertThat(inBuffer, equalTo(inBefore));
      assertThat(outBuffer, not(equalTo(outBefore)));

      // Act (decrypt back into input buffer)
      byte[] outSnapshot = outBuffer.clone();
      crypt.decrypt(outBuffer, outHeader, originalPlaintext.length, inBuffer, inFooter);

      // Assert (output unchanged by decrypt, input slice equals original)
      assertThat(outSnapshot, equalTo(outBuffer));
      assertArrayEquals(
          originalPlaintext,
          Arrays.copyOfRange(inBuffer, inFooter, inFooter + originalPlaintext.length),
          "CryptByteBufferType: " + type.name());
    }
  }

  @Test
  void encryptDecrypt_whenCipherReusedOnByteBuffer_expectOriginalPlaintext()
      throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt;
      byte[] originalData = Hex.decode(plainText[i]);
      int len = originalData.length;
      ByteBuffer plain = ByteBuffer.wrap(originalData);
      if (ivs[i] == null) {
        crypt = new CryptByteBuffer(type, keys[i]);
      } else {
        crypt = new CryptByteBuffer(type, keys[i], ivs[i]);
      }
      ByteBuffer ciphertext1 = crypt.encryptCopy(plain);
      ByteBuffer ciphertext2 = crypt.encryptCopy(plain);
      ByteBuffer ciphertext3 = crypt.encryptCopy(plain);
      assertEquals(ciphertext1.capacity(), len);
      assertEquals(ciphertext2.capacity(), len);
      assertEquals(ciphertext3.capacity(), len);
      assertEquals(ciphertext1.remaining(), len);
      assertEquals(ciphertext2.remaining(), len);
      assertEquals(ciphertext3.remaining(), len);

      if (type.isStreamCipher) {
        // Once we have initialised the cipher, it is treated as a stream.
        // Repeated encryption of the same data will return different ciphertext,
        // as it is treated as a later point in the stream.
        assertThat(ciphertext1, not(equalTo(ciphertext2)));
        assertThat(ciphertext1, not(equalTo(ciphertext3)));
        assertThat(ciphertext2, not(equalTo(ciphertext3)));
      }

      ByteBuffer decipheredtext1 = crypt.decryptCopy(ciphertext1);
      ByteBuffer decipheredtext2 = crypt.decryptCopy(ciphertext2);
      ByteBuffer decipheredtext3 = crypt.decryptCopy(ciphertext3);
      assertThat("CryptByteBufferType: " + type.name(), plain, equalTo(decipheredtext1));
      assertThat("CryptByteBufferType: " + type.name(), plain, equalTo(decipheredtext2));
      assertThat("CryptByteBufferType: " + type.name(), plain, equalTo(decipheredtext3));
    }
  }

  @Test
  void encrypt_whenByteBufferWrap_expectNoInputMutationAndExpectedCiphertext()
      throws GeneralSecurityException {
    int header = 5;
    int footer = 5;
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt;
      CryptByteBuffer crypt2;
      byte[] origPlaintext = Hex.decode(plainText[i]);
      byte[] buf = new byte[origPlaintext.length + header + footer];
      System.arraycopy(origPlaintext, 0, buf, header, origPlaintext.length);
      byte[] before = buf.clone();
      if (ivs[i] == null) {
        crypt = new CryptByteBuffer(type, keys[i]);
        crypt2 = new CryptByteBuffer(type, keys[i]);
      } else {
        crypt = new CryptByteBuffer(type, keys[i], ivs[i]);
        crypt2 = new CryptByteBuffer(type, keys[i], ivs[i]);
      }
      ByteBuffer plaintext = ByteBuffer.wrap(buf, header, origPlaintext.length);

      // Act
      ByteBuffer ciphertext = crypt.encryptCopy(plaintext);

      // Assert (input not mutated, lengths match)
      assertThat(buf, equalTo(before));
      assertEquals(origPlaintext.length, ciphertext.remaining());

      // Arrange (reference ciphertext)
      byte[] ref = crypt2.encryptCopy(origPlaintext);

      // Assert (ciphertext matches reference)
      byte[] got = new byte[origPlaintext.length];
      ciphertext.get(got);
      ciphertext.position(0);
      assertThat(ref, equalTo(got));

      // Act (decrypt copy)
      ByteBuffer deciphered = crypt.decryptCopy(ciphertext);

      // Assert (buffers equal and bytes equal)
      assertThat(deciphered, equalTo(plaintext));
      byte[] data = new byte[origPlaintext.length];
      deciphered.get(data);
      assertThat(data, equalTo(origPlaintext));
    }
  }

  @Test
  void encrypt_whenByteBufferToByteBuffer_expectPositionsAdvancedAndOutputChanged()
      throws GeneralSecurityException {
    int header = 5;
    int footer = 5;
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] origPlaintext = Hex.decode(plainText[i]);
      byte[] buf = new byte[origPlaintext.length + header + footer];
      System.arraycopy(origPlaintext, 0, buf, header, origPlaintext.length);
      byte[] before = buf.clone();
      ByteBuffer plaintext = ByteBuffer.wrap(buf, header, origPlaintext.length);
      byte[] ciphertextBuf = new byte[origPlaintext.length + header + footer];
      byte[] outBefore = ciphertextBuf.clone();
      ByteBuffer ciphertext = ByteBuffer.wrap(ciphertextBuf, header, origPlaintext.length);

      // Act (encrypt)
      crypt.encrypt(plaintext, ciphertext);

      // Assert (positions advanced, input not mutated, output mutated)
      assertEquals(header + origPlaintext.length, plaintext.position());
      assertEquals(header + origPlaintext.length, ciphertext.position());
      assertThat(buf, equalTo(before));
      plaintext.position(header);
      ciphertext.position(header);
      assertThat(ciphertextBuf, not(equalTo(outBefore)));

      // Act (zero input then decrypt back)
      Arrays.fill(buf, (byte) 0);
      assertThat(buf, not(equalTo(before)));
      crypt.decrypt(ciphertext, plaintext);

      // Assert (restored input)
      assertThat(buf, equalTo(before));
    }
  }

  @Test
  void encryptDecrypt_whenDirectByteBuffers_expectOriginalPlaintext()
      throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] origPlaintext = Hex.decode(plainText[i]);
      ByteBuffer plaintext = ByteBuffer.allocateDirect(origPlaintext.length);
      plaintext.put(origPlaintext);
      plaintext.position(0);
      ByteBuffer ciphertext = ByteBuffer.allocateDirect(origPlaintext.length);

      // Act (encrypt)
      crypt.encrypt(plaintext, ciphertext);

      // Assert (positions advanced; ciphertext differs)
      assertEquals(origPlaintext.length, plaintext.position());
      assertEquals(origPlaintext.length, ciphertext.position());
      plaintext.position(0);
      ciphertext.position(0);
      byte[] ciphertextCopy = new byte[origPlaintext.length];
      ciphertext.get(ciphertextCopy);
      ciphertext.position(0);
      assertFalse(Arrays.equals(origPlaintext, ciphertextCopy));

      // Act (decrypt)
      crypt.decrypt(ciphertext, plaintext);

      // Assert (positions advanced and bytes restored)
      assertEquals(origPlaintext.length, plaintext.position());
      assertEquals(origPlaintext.length, ciphertext.position());
      assertEquals(plaintext, ciphertext);
      plaintext.position(0);
      byte[] finalPlaintext = new byte[origPlaintext.length];
      plaintext.get(finalPlaintext);
      assertArrayEquals(finalPlaintext, origPlaintext);
    }
  }

  @Test
  void decrypt_whenByteBufferWrap_expectNoInputMutationAndOriginalPlaintext()
      throws GeneralSecurityException {
    int header = 5;
    int footer = 5;
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] origPlaintext = Hex.decode(plainText[i]);
      byte[] buf = origPlaintext.clone();
      ByteBuffer plaintext = ByteBuffer.wrap(buf);

      // Act (encrypt to separate buffer)
      ByteBuffer ciphertext = crypt.encryptCopy(plaintext);

      // Assert (input not modified, lengths match)
      assertThat(buf, equalTo(origPlaintext));
      assertEquals(origPlaintext.length, ciphertext.remaining());

      // Arrange (copy ciphertext into offset buffer)
      byte[] decryptBuf = new byte[header + origPlaintext.length + footer];
      ciphertext.get(decryptBuf, header, origPlaintext.length);
      byte[] decryptBufBefore = decryptBuf.clone();
      ByteBuffer toDecipher = ByteBuffer.wrap(decryptBuf, header, origPlaintext.length);

      // Act (decrypt copy)
      ByteBuffer deciphered = crypt.decryptCopy(toDecipher);

      // Assert (source unchanged; result equals original)
      assertThat(decryptBuf, equalTo(decryptBufBefore));
      assertThat(deciphered, equalTo(plaintext));
      byte[] data = new byte[origPlaintext.length];
      deciphered.get(data);
      assertThat(data, equalTo(origPlaintext));
    }
  }

  @Test
  void encryptDecrypt_whenDirectByteBufferRoundTrip_expectOriginalPlaintext()
      throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] origPlaintext = Hex.decode(plainText[i]);
      ByteBuffer plaintext = ByteBuffer.allocateDirect(origPlaintext.length);
      plaintext.put(origPlaintext);
      plaintext.flip();

      // Act (encrypt to copy)
      ByteBuffer ciphertext = crypt.encryptCopy(plaintext);

      // Assert (ciphertext length)
      assertEquals(origPlaintext.length, ciphertext.remaining());

      // Assert (plaintext buffer content unchanged)
      ByteBuffer plCopy = plaintext.duplicate();
      plCopy.clear();
      byte[] gotPlain = new byte[origPlaintext.length];
      plCopy.get(gotPlain);
      assertArrayEquals(origPlaintext, gotPlain);

      // Act (decrypt copy)
      ByteBuffer deciphered = crypt.decryptCopy(ciphertext);

      // Assert (round-trip equals original)
      byte[] data = new byte[origPlaintext.length];
      deciphered.get(data);
      assertArrayEquals(origPlaintext, data);
    }
  }

  @Test
  void decrypt_whenNewInstanceAfterEncrypt_expectOriginalPlaintext()
      throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] plain = Hex.decode(plainText[i]);

      // Act (encrypt three times with same instance)
      byte[] ciphertext1 = crypt.encryptCopy(plain);
      byte[] ciphertext2 = crypt.encryptCopy(plain);
      byte[] ciphertext3 = crypt.encryptCopy(plain);

      // Assert (stream ciphers: subsequent ciphertexts differ)
      if (type.isStreamCipher) {
        assertFalse(Arrays.equals(ciphertext1, ciphertext2));
        assertFalse(Arrays.equals(ciphertext1, ciphertext3));
        assertFalse(Arrays.equals(ciphertext2, ciphertext3));
      }

      // Arrange (fresh instance for decryption)
      crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);

      // Act (decrypt)
      byte[] dec1 = crypt.decryptCopy(ciphertext1);
      byte[] dec2 = crypt.decryptCopy(ciphertext2);
      byte[] dec3 = crypt.decryptCopy(ciphertext3);

      // Assert (round-trip equals original)
      assertArrayEquals(plain, dec1, "CryptByteBufferType: " + type.name());
      assertArrayEquals(plain, dec2, "CryptByteBufferType2: " + type.name());
      assertArrayEquals(plain, dec3, "CryptByteBufferType3: " + type.name());
    }
  }

  @Test
  void encrypt_whenNullByteArray_expectNullPointerException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);

      // Act & Assert
      assertThrows(
          NullPointerException.class,
          () -> crypt.encryptCopy((byte[]) null),
          "CryptByteBufferType: " + type.name());
    }
  }

  @Test
  void encrypt_whenNullArrayWithRange_expectException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      int len = plainText[i].length();

      // Act
      RuntimeException ex =
          assertThrows(
              RuntimeException.class,
              () -> crypt.encryptCopy(null, 0, len),
              "CryptByteBufferType: " + type.name());

      // Assert (type)
      assertTrue(
          ex instanceof IllegalArgumentException || ex instanceof NullPointerException,
          "Unexpected exception type: " + ex.getClass());
    }
  }

  @Test
  void encrypt_whenOffsetOutOfBounds_expectException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] data = Hex.decode(plainText[i]);
      int badOff = -3;
      int badLen = plainText[i].length() - 3;

      // Act
      RuntimeException ex =
          assertThrows(
              RuntimeException.class,
              () -> crypt.encryptCopy(data, badOff, badLen),
              "CryptByteBufferType: " + type.name());

      // Assert (type)
      assertTrue(
          ex instanceof IllegalArgumentException || ex instanceof IndexOutOfBoundsException,
          "Unexpected exception type: " + ex.getClass());
    }
  }

  @Test
  void encrypt_whenLengthOutOfBounds_expectException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] data = Hex.decode(plainText[i]);
      int badLen = plainText[i].length() + 3;

      // Act
      RuntimeException ex =
          assertThrows(
              RuntimeException.class,
              () -> crypt.encryptCopy(data, 0, badLen),
              "CryptByteBufferType: " + type.name());

      // Assert (type)
      assertTrue(
          ex instanceof IllegalArgumentException || ex instanceof IndexOutOfBoundsException,
          "Unexpected exception type: " + ex.getClass());
    }
  }

  @Test
  void decrypt_whenNullByteArray_expectNullPointerException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);

      // Act & Assert
      assertThrows(
          NullPointerException.class,
          () -> crypt.decryptCopy((byte[]) null),
          "CryptByteBufferType: " + type.name());
    }
  }

  @Test
  void decrypt_whenNullArrayWithRange_expectException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      int len = plainText[i].length();

      // Act
      RuntimeException ex =
          assertThrows(
              RuntimeException.class,
              () -> crypt.decryptCopy(null, 0, len),
              "CryptByteBufferType: " + type.name());

      // Assert (type)
      assertTrue(
          ex instanceof NullPointerException || ex instanceof IllegalArgumentException,
          "Unexpected exception type: " + ex.getClass());
    }
  }

  @Test
  void decrypt_whenOffsetOutOfBounds_expectException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] data = Hex.decode(plainText[i]);
      int badOff = -3;
      int badLen = plainText[i].length() - 3;

      // Act
      RuntimeException ex =
          assertThrows(
              RuntimeException.class,
              () -> crypt.decryptCopy(data, badOff, badLen),
              "CryptByteBufferType: " + type.name());

      // Assert (type)
      assertTrue(
          ex instanceof IllegalArgumentException || ex instanceof IndexOutOfBoundsException,
          "Unexpected exception type: " + ex.getClass());
    }
  }

  @Test
  void decrypt_whenLengthOutOfBounds_expectException() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      // Arrange
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt =
          (ivs[i] == null)
              ? new CryptByteBuffer(type, keys[i])
              : new CryptByteBuffer(type, keys[i], ivs[i]);
      byte[] data = Hex.decode(plainText[i]);
      int badLen = plainText[i].length() + 3;

      // Act
      RuntimeException ex =
          assertThrows(
              RuntimeException.class,
              () -> crypt.decryptCopy(data, 0, badLen),
              "CryptByteBufferType: " + type.name());

      // Assert (type)
      assertTrue(
          ex instanceof IllegalArgumentException || ex instanceof IndexOutOfBoundsException,
          "Unexpected exception type: " + ex.getClass());
    }
  }

  @Test
  void getIV_whenConstructedWithIv_expectSameIv()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    int i = 1; // CHACHA_128 after enum cleanup (AESCTR=0, CHACHA_128=1)
    CryptByteBuffer crypt = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    assertArrayEquals(ivs[i], crypt.getIV().getIV());
  }

  @Test
  void setIV_whenIvParameterSpecProvided_expectIvUpdated()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    int i = 1; // CHACHA_128 after enum cleanup
    CryptByteBuffer crypt = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    crypt.genIV();
    crypt.setIV(new IvParameterSpec(ivs[i]));
    assertArrayEquals(ivs[i], crypt.getIV().getIV());
  }

  @Test
  void serialization_preservesStreamPosition_and_iv() throws Exception {
    // Arrange (AESCTR)
    int i = 0;
    CryptByteBuffer original = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    byte[] plain = Hex.decode(IV_PLAIN_TEXT);
    int split = (plain.length / 3) + 7; // arbitrary split not on block boundary

    // Act (process some bytes, then serialize + deserialize)
    byte[] part1 = original.encryptCopy(plain, 0, split);
    java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
    try (java.io.ObjectOutputStream oout = new java.io.ObjectOutputStream(bout)) {
      oout.writeObject(original);
    }
    byte[] ser = bout.toByteArray();
    CryptByteBuffer restored;
    try (java.io.ObjectInputStream oin =
        new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(ser))) {
      Object obj = oin.readObject();
      assertNotNull(obj);
      assertInstanceOf(CryptByteBuffer.class, obj);
      restored = (CryptByteBuffer) obj;
    }

    // Assert (IV survived)
    assertArrayEquals(ivs[i], restored.getIV().getIV());

    // Act (continue stream after deserialization)
    byte[] part2 = restored.encryptCopy(plain, split, plain.length - split);
    byte[] combined = new byte[plain.length];
    System.arraycopy(part1, 0, combined, 0, part1.length);
    System.arraycopy(part2, 0, combined, part1.length, part2.length);

    // Reference: continuous stream without serialization
    CryptByteBuffer ref = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    byte[] refFull = ref.encryptCopy(plain);

    // Assert (keystream continuity preserved across serialization)
    assertArrayEquals(refFull, combined);

    // Round-trip decrypt also matches
    CryptByteBuffer dec = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    assertArrayEquals(plain, dec.decryptCopy(refFull));
  }

  @Test
  void setIV_whenNullIvParameterSpec_expectInvalidAlgorithmParameterException()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    int i = 1; // CHACHA_128 after enum cleanup
    CryptByteBuffer crypt = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    assertThrows(InvalidAlgorithmParameterException.class, () -> crypt.setIV(null));
  }

  @Test
  void genIV_whenCalled_expectNonNull()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    int i = 1; // CHACHA_128 after enum cleanup
    CryptByteBuffer crypt = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    assertNotNull(crypt.genIV());
  }

  @Test
  void genIV_whenCalled_expectCorrectLength()
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    int i = 1; // CHACHA_128 after enum cleanup
    CryptByteBuffer crypt = new CryptByteBuffer(cipherTypes[i], keys[i], ivs[i]);
    assertNotNull(cipherTypes[i].ivSize);
    assertEquals(crypt.genIV().getIV().length, cipherTypes[i].ivSize.intValue());
  }

  @Test
  void encrypt_whenOverlappingOutput_expectCorrectResult() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt, crypt2;

      if (ivs[i] == null) {
        crypt = new CryptByteBuffer(type, keys[i]);
        crypt2 = new CryptByteBuffer(type, keys[i]);
      } else {
        crypt = new CryptByteBuffer(type, keys[i], ivs[i]);
        crypt2 = new CryptByteBuffer(type, keys[i], ivs[i]);
      }
      byte[] originalPlaintext = Hex.decode(plainText[i]);
      byte[] originalCiphertext = crypt2.encryptCopy(originalPlaintext);
      byte[] buf = new byte[originalPlaintext.length + 1];
      System.arraycopy(originalPlaintext, 0, buf, 0, originalPlaintext.length);
      crypt.encrypt(buf, 0, originalPlaintext.length, buf, 1);
      assertArrayEquals(originalCiphertext, Arrays.copyOfRange(buf, 1, buf.length));
    }
  }

  @Test
  void decrypt_whenOverlappingOutput_expectCorrectResult() throws GeneralSecurityException {
    for (int i = 0; i < cipherTypes.length; i++) {
      CryptByteBufferType type = cipherTypes[i];
      CryptByteBuffer crypt, crypt2;

      if (ivs[i] == null) {
        crypt = new CryptByteBuffer(type, keys[i]);
        crypt2 = new CryptByteBuffer(type, keys[i]);
      } else {
        crypt = new CryptByteBuffer(type, keys[i], ivs[i]);
        crypt2 = new CryptByteBuffer(type, keys[i], ivs[i]);
      }
      byte[] originalPlaintext = Hex.decode(plainText[i]);
      byte[] originalCiphertext = crypt2.encryptCopy(originalPlaintext);
      byte[] buf = new byte[originalPlaintext.length + 1];
      System.arraycopy(originalCiphertext, 0, buf, 0, originalCiphertext.length);
      crypt.decrypt(buf, 0, originalCiphertext.length, buf, 1);
      assertArrayEquals(originalPlaintext, Arrays.copyOfRange(buf, 1, buf.length));
    }
  }
}
