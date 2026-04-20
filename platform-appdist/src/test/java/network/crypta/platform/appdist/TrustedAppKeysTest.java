package network.crypta.platform.appdist;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustedAppKeysTest {
  @TempDir Path tempDir;

  @Test
  void load_whenTrustedKeysFileStartsWithUtf8Bom_expectTrustedKeyParsed() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("trusted-keys.properties");
    Files.writeString(
        trustedKeysFile,
        "\uFEFF"
            + """
            trusted.keys.version=1
            key.0.id=local-dev
            key.0.algorithm=Ed25519
            key.0.public.key.base64=%s
            """
                .formatted(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())),
        StandardCharsets.UTF_8);

    TrustedAppKeys trustedKeys = TrustedAppKeys.load(trustedKeysFile);

    assertTrue(trustedKeys.find("local-dev").isPresent());
  }
}
