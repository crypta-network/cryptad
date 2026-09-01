package network.crypta.platform.appcatalog;

import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class StoredCatalogSourceTest {
  @Test
  void compatibilityConstructor_whenTrustBindingIsUnavailable_expectLegacyDefaults() {
    Instant storedAt = Instant.parse("2026-09-01T00:00:00Z");
    AppCatalogSource source = AppCatalogSource.parse("https://catalog.example/catalog.properties");
    FetchedCatalog fetchedCatalog = new FetchedCatalog(new byte[] {1}, new byte[] {2});

    StoredCatalogSource stored =
        new StoredCatalogSource(
            "core",
            source,
            storedAt,
            storedAt,
            AppCatalogSourceRefreshMetadata.success(storedAt, source.displayUri()),
            fetchedCatalog);

    assertTrue(stored.trustBindingId().isEmpty());
    assertTrue(stored.trustBindingDigest().isEmpty());
    assertTrue(stored.mirrorHealth().isEmpty());
    assertEquals(1, stored.mirrors().size());
    assertEquals(AppCatalogMirror.primary(source, storedAt), stored.mirrors().getFirst());
  }
}
