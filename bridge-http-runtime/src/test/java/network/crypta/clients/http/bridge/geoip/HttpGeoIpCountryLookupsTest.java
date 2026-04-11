package network.crypta.clients.http.bridge.geoip;

import java.io.IOException;
import java.nio.file.Path;
import network.crypta.clients.http.geoip.IPConverter;
import network.crypta.node.Node;
import network.crypta.node.ProgramDirectory;
import network.crypta.runtime.admin.geoip.GeoIpCountryInfo;
import network.crypta.support.http.StaticResourcePaths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class HttpGeoIpCountryLookupsTest {

  @Test
  void forNode_whenNodeIsNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> HttpGeoIpCountryLookups.forNode(null));
  }

  @Test
  void forNode_whenNodeProvided_expectLookupUsesIpv4CountryFile(@TempDir Path tempDir)
      throws IOException {
    ProgramDirectory runDir = new ProgramDirectory();
    runDir.move(tempDir.toString());
    Node node = mock(Node.class);
    when(node.runDir()).thenReturn(runDir);
    java.io.File expectedFile = tempDir.resolve("IpToCountry.dat").toFile();
    byte[] ipAddressBytes = new byte[] {127, 0, 0, 1};
    IPConverter converter = mock(IPConverter.class);
    when(converter.locateIP(ipAddressBytes)).thenReturn(IPConverter.Country.US);

    try (MockedStatic<IPConverter> ipConverter = mockStatic(IPConverter.class)) {
      ipConverter.when(() -> IPConverter.getInstance(expectedFile)).thenReturn(converter);

      GeoIpCountryInfo info = HttpGeoIpCountryLookups.forNode(node).locate(ipAddressBytes);

      assertNotNull(info);
      assertEquals(IPConverter.Country.US.getName(), info.displayName());
      assertEquals(
          StaticResourcePaths.ROOT_URL + IPConverter.Country.US.getFlagIconPath(),
          info.staticFlagUrl());
      ipConverter.verify(() -> IPConverter.getInstance(expectedFile));
      verify(converter).locateIP(ipAddressBytes);
    }
  }
}
