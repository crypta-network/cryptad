package network.crypta.runtime.admin.geoip;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class GeoIpCountryInfoTest {

  @Test
  void constructor_whenDisplayNameNull_expectNullPointerException() {
    // Arrange / Act / Assert
    assertThrows(NullPointerException.class, () -> new GeoIpCountryInfo(null, "/static/flag.png"));
  }

  @Test
  void constructor_whenStaticFlagUrlNull_expectRecordCreated() {
    // Arrange / Act
    GeoIpCountryInfo info = new GeoIpCountryInfo("United States", null);

    // Assert
    assertEquals("United States", info.displayName());
    assertNull(info.staticFlagUrl());
  }
}
