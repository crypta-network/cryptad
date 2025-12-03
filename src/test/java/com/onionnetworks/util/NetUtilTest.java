package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class NetUtilTest {

  @Test
  void getIpUrlsByName_whenHostMissing_returnsOriginalUrl() throws IOException {
    URL url = URI.create("http:/dir/foobar?param&adsf=2312#anc").toURL();

    URL[] result = NetUtil.getIpUrlsByName(url);

    assertEquals(1, result.length);
    assertSame(url, result[0]);
  }

  @Test
  void getIpUrlsByName_whenHostPresent_returnsUrlsForEachResolvedAddress() throws IOException {
    URL url = URI.create("http://user:pass@localhost:14234/dir/foobar?param&adsf=2312#anc").toURL();

    InetAddress[] addrs = InetAddress.getAllByName("localhost");
    List<String> expectedExternalForms =
        Arrays.stream(addrs)
            .map(
                addr ->
                    buildUri(
                            url.getProtocol(),
                            url.getUserInfo(),
                            addr.getHostAddress(),
                            url.getPort(),
                            url.getPath(),
                            url.getQuery(),
                            url.getRef())
                        .toString())
            .toList();

    URL[] result = NetUtil.getIpUrlsByName(url);
    List<String> actualExternalForms = Arrays.stream(result).map(URL::toString).toList();

    assertEquals(expectedExternalForms, actualExternalForms);
    assertEquals(expectedExternalForms, List.copyOf(expectedExternalForms));
    assertEquals(actualExternalForms, List.copyOf(actualExternalForms));
  }

  private static URI buildUri(
      String scheme,
      String userInfo,
      String host,
      int port,
      String path,
      String query,
      String fragment) {
    try {
      return new URI(scheme, userInfo, host, port, path, query, fragment);
    } catch (Exception e) {
      throw new IllegalStateException("Unexpected URI error while building test expectation", e);
    }
  }
}
