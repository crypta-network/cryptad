package network.crypta.platform.api;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class PlatformApiResponseTest {
  @Test
  void reasonPhrase_whenGatewayStatusCodesUsed_expectStandardPhrases() {
    assertEquals("Unsupported Media Type", PlatformApiResponse.reasonPhrase(415));
    assertEquals("Bad Gateway", PlatformApiResponse.reasonPhrase(502));
    assertEquals("Service Unavailable", PlatformApiResponse.reasonPhrase(503));
    assertEquals("Gateway Timeout", PlatformApiResponse.reasonPhrase(504));
  }
}
