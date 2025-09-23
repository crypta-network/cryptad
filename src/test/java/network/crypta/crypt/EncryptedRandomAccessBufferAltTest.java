package network.crypta.crypt;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Security;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import network.crypta.support.io.RandomAccessBufferTestBase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EncryptedRandomAccessBufferAltTest extends RandomAccessBufferTestBase {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public EncryptedRandomAccessBufferAltTest() {
    super(TEST_LIST);
  }

  @Override
  protected RandomAccessBuffer construct(long size) throws IOException {
    ByteArrayRandomAccessBuffer barat =
        new ByteArrayRandomAccessBuffer((int) (size + types[0].headerLen));
    try {
      return new EncryptedRandomAccessBuffer(types[0], barat, secret, true);
    } catch (GeneralSecurityException e) {
      throw new Error(e);
    }
  }

  private static final EncryptedRandomAccessBufferType[] types =
      EncryptedRandomAccessBufferType.values();
  private static final MasterSecret secret = new MasterSecret();
  private static final int[] TEST_LIST =
      new int[] {0, 1, 32, 64, 32768, 1024 * 1024, 1024 * 1024 + 1};
}
