package network.crypta.clients.http.bridge.geoip;

import java.io.File;
import network.crypta.clients.http.geoip.IPConverter;
import network.crypta.runtime.admin.geoip.GeoIpCountryInfo;
import network.crypta.support.http.StaticResourcePaths;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class HttpGeoIpCountryLookupTest {

  @Test
  void constructor_whenDbFileNull_expectNullPointerException() {
    // Arrange / Act / Assert
    assertThrows(NullPointerException.class, () -> new HttpGeoIpCountryLookup(null));
  }

  @Test
  void locate_whenCountryHasFlag_expectCountryInfoWithFullStaticFlagUrl() {
    // Arrange
    File dbFile = new File("build/tmp/geoip.dat");
    byte[] ipAddressBytes = new byte[] {0, 0, 0, 1};
    IPConverter converter = mock(IPConverter.class);
    when(converter.locateIP(ipAddressBytes)).thenReturn(IPConverter.Country.US);

    try (MockedStatic<IPConverter> ipConverter = mockStatic(IPConverter.class)) {
      ipConverter.when(() -> IPConverter.getInstance(dbFile)).thenReturn(converter);
      HttpGeoIpCountryLookup lookup = new HttpGeoIpCountryLookup(dbFile);

      // Act
      GeoIpCountryInfo info = lookup.locate(ipAddressBytes);

      // Assert
      assertNotNull(info);
      assertEquals(IPConverter.Country.US.getName(), info.displayName());
      assertEquals(
          StaticResourcePaths.ROOT_URL + IPConverter.Country.US.getFlagIconPath(),
          info.staticFlagUrl());
      verify(converter).locateIP(ipAddressBytes);
    }
  }

  @Test
  void locate_whenCountryHasNoFlag_expectCountryInfoWithNullStaticFlagUrl() {
    // Arrange
    File dbFile = new File("build/tmp/geoip.dat");
    byte[] ipAddressBytes = new byte[] {0, 0, 0, 2};
    IPConverter converter = mock(IPConverter.class);
    when(converter.locateIP(ipAddressBytes)).thenReturn(IPConverter.Country.ZZ);

    try (MockedStatic<IPConverter> ipConverter = mockStatic(IPConverter.class)) {
      ipConverter.when(() -> IPConverter.getInstance(dbFile)).thenReturn(converter);
      HttpGeoIpCountryLookup lookup = new HttpGeoIpCountryLookup(dbFile);

      // Act
      GeoIpCountryInfo info = lookup.locate(ipAddressBytes);

      // Assert
      assertNotNull(info);
      assertEquals(IPConverter.Country.ZZ.getName(), info.displayName());
      assertNull(info.staticFlagUrl());
      verify(converter).locateIP(ipAddressBytes);
    }
  }

  @Test
  void locate_whenCountryIsUnknown_expectNull() {
    // Arrange
    File dbFile = new File("build/tmp/geoip.dat");
    byte[] ipAddressBytes = new byte[] {0, 0, 0, 3};
    IPConverter converter = mock(IPConverter.class);
    when(converter.locateIP(ipAddressBytes)).thenReturn(null);

    try (MockedStatic<IPConverter> ipConverter = mockStatic(IPConverter.class)) {
      ipConverter.when(() -> IPConverter.getInstance(dbFile)).thenReturn(converter);
      HttpGeoIpCountryLookup lookup = new HttpGeoIpCountryLookup(dbFile);

      // Act
      GeoIpCountryInfo info = lookup.locate(ipAddressBytes);

      // Assert
      assertNull(info);
      verify(converter).locateIP(ipAddressBytes);
    }
  }
}
