package network.crypta.node;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OpennetNoderefValidatorTest {

  private static final String KEY_IDENTITY = "identity";
  private static final String KEY_OPENNET = "opennet";

  @Test
  void validateNoderef_whenValidCompressedNoderef_expectParsedFieldSetAndIdentityRegistered() {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.put(KEY_OPENNET, true);
    String identity = "identity-1";
    fieldSet.putSingle(KEY_IDENTITY, identity);
    byte[] noderef = buildNoderef(fieldSet, true, false);

    try (MockedStatic<OpennetManager> manager = Mockito.mockStatic(OpennetManager.class)) {
      // Act
      SimpleFieldSet parsed = OpennetNoderefValidator.validateNoderef(noderef, null, false);

      // Assert
      assertNotNull(parsed);
      assertTrue(parsed.getBoolean(KEY_OPENNET, false));
      assertEquals(identity, parsed.get(KEY_IDENTITY));
      manager.verify(() -> OpennetManager.registerKnownIdentity(identity));
    }
  }

  @Test
  void validateNoderef_whenIdentityMissing_expectNoRegistrationAndRefReturned() {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.put(KEY_OPENNET, true);
    byte[] noderef = buildNoderef(fieldSet, false, false);

    try (MockedStatic<OpennetManager> manager = Mockito.mockStatic(OpennetManager.class)) {
      // Act
      SimpleFieldSet parsed = OpennetNoderefValidator.validateNoderef(noderef, null, false);

      // Assert
      assertNotNull(parsed);
      assertTrue(parsed.getBoolean(KEY_OPENNET, false));
      manager.verifyNoInteractions();
    }
  }

  @Test
  void validateNoderef_whenOpennetMissingAndForceEnabled_expectInjectedOpennetAndSuccess() {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    String identity = "identity-2";
    fieldSet.putSingle(KEY_IDENTITY, identity);
    byte[] noderef = buildNoderef(fieldSet, false, false);

    try (MockedStatic<OpennetManager> manager = Mockito.mockStatic(OpennetManager.class)) {
      // Act
      SimpleFieldSet parsed = OpennetNoderefValidator.validateNoderef(noderef, null, true);

      // Assert
      assertNotNull(parsed);
      assertTrue(parsed.getBoolean(KEY_OPENNET, false));
      manager.verify(() -> OpennetManager.registerKnownIdentity(identity));
    }
  }

  @Test
  void validateNoderef_whenOpennetFalseAndForceEnabled_expectNull() {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.put(KEY_OPENNET, false);
    fieldSet.putSingle(KEY_IDENTITY, "identity-3");
    byte[] noderef = buildNoderef(fieldSet, false, false);

    try (MockedStatic<OpennetManager> manager = Mockito.mockStatic(OpennetManager.class)) {
      // Act
      SimpleFieldSet parsed = OpennetNoderefValidator.validateNoderef(noderef, null, true);

      // Assert
      assertNull(parsed);
      manager.verifyNoInteractions();
    }
  }

  @Test
  void validateNoderef_whenOpennetMissingAndForceDisabled_expectNull() {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.putSingle(KEY_IDENTITY, "identity-4");
    byte[] noderef = buildNoderef(fieldSet, false, false);

    // Act
    SimpleFieldSet parsed = OpennetNoderefValidator.validateNoderef(noderef, null, false);

    // Assert
    assertNull(parsed);
  }

  @Test
  void validateNoderef_whenPayloadTooShort_expectNull() {
    // Arrange
    byte[] noderef = new byte[] {0, 1, 2, 3, 4};

    // Act
    SimpleFieldSet parsed = OpennetNoderefValidator.validateNoderef(noderef, null, false);

    // Assert
    assertNull(parsed);
  }

  @Test
  void validateNoderef_whenDsaCompressedFlagSet_expectParsedFieldSet() {
    // Arrange
    SimpleFieldSet fieldSet = new SimpleFieldSet(true);
    fieldSet.put(KEY_OPENNET, true);
    byte[] noderef = buildNoderef(fieldSet, false, true);

    // Act
    SimpleFieldSet parsed = OpennetNoderefValidator.validateNoderef(noderef, null, false);

    // Assert
    assertNotNull(parsed);
    assertTrue(parsed.getBoolean(KEY_OPENNET, false));
  }

  private static byte[] buildNoderef(
      SimpleFieldSet fieldSet, boolean compressed, boolean includeDsaCompressedFlag) {
    byte[] payload = fieldSet.toOrderedString().getBytes(StandardCharsets.UTF_8);
    int flags = 0;
    if (compressed) {
      flags |= 1;
    }
    if (includeDsaCompressedFlag) {
      flags |= 2;
    }

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(flags);
    if (includeDsaCompressedFlag) {
      out.write(0);
    }

    if (compressed) {
      try (Deflater deflater = new Deflater()) {
        deflater.setInput(payload);
        deflater.finish();
        byte[] buffer = new byte[256];
        while (!deflater.finished()) {
          int count = deflater.deflate(buffer);
          out.write(buffer, 0, count);
        }
      }
    } else {
      out.write(payload, 0, payload.length);
    }

    return out.toByteArray();
  }
}
