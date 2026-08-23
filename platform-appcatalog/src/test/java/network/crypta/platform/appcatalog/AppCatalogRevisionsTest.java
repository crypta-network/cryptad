package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class AppCatalogRevisionsTest {
  private static final String EXPECTED_REVISION_DIGEST =
      "sha256:34dd007a638a11fc22055d9465d0b90bc631fc33060c309b66aded49f92f4b4c";

  @Test
  void catalogDigest_whenExactSidecarsProvided_expectLengthPrefixedPairDigest() {
    byte[] catalog =
        "catalog.id=crypta-stable-apps\ncatalog.channel=stable\n".getBytes(StandardCharsets.UTF_8);
    byte[] signature =
        "schemaVersion=1\nkeyId=stable-catalog-fixture-1\nsignature=fixture\n"
            .getBytes(StandardCharsets.UTF_8);
    FetchedCatalog fetchedCatalog = new FetchedCatalog(catalog, signature);

    String revisionDigest = AppCatalogRevisions.catalogDigest(fetchedCatalog);
    String contentDigest = AppCatalogRevisions.catalogContentDigest(fetchedCatalog);

    assertEquals(EXPECTED_REVISION_DIGEST, revisionDigest);
    assertNotEquals(contentDigest, revisionDigest);
  }
}
