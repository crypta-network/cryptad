package network.crypta.platform.appcatalog;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Public source-code reference metadata included in a submission package.
 *
 * <p>The URL is normalized and must be absolute. Local file URLs are intentionally rejected because
 * review packages should be portable and must not expose reviewer or author filesystem paths. HTTP
 * and HTTPS references must identify a public host; loopback, private IPv4, local IPv6, hostless,
 * and equivalent legacy address spellings are rejected before metadata is serialized.
 *
 * <p>{@code crypta:} references are allowed when they point to public fetch material. Private
 * insert keys are rejected here and again by the redaction scanner so source metadata cannot leak
 * author publishing keys through generic URL fields. The optional revision is a bounded public
 * identifier, such as a commit hash or release tag, not a secret branch name or local checkout
 * path.
 *
 * @param url public source URL using {@code https}, {@code http}, or {@code crypta}
 * @param revision optional bounded public revision identifier
 */
public record AppSubmissionSourceReference(URI url, Optional<String> revision) {
  private static final int MAX_REVISION_CHARS = 128;
  private static final String SOURCE_REFERENCE_FIELD = "sourceReference";
  private static final String URL_FIELD = "url";
  private static final String REVISION_FIELD = "revision";
  private static final String SOURCE_REFERENCE_URL_FIELD = SOURCE_REFERENCE_FIELD + "." + URL_FIELD;
  private static final String SOURCE_REFERENCE_REVISION_FIELD =
      SOURCE_REFERENCE_FIELD + "." + REVISION_FIELD;

  /**
   * Creates validated source reference metadata.
   *
   * <p>The constructor normalizes the URI, rejects user-info and fragments, enforces the supported
   * scheme set, and checks HTTP-family hosts for public reachability semantics. It does not perform
   * network DNS resolution; validation is based on URI structure and literal host classification so
   * package creation remains hermetic.
   */
  public AppSubmissionSourceReference {
    url = requirePublicUri(url);
    revision =
        Objects.requireNonNull(revision, REVISION_FIELD)
            .map(
                value ->
                    AppCatalogSidecars.requireBoundedSingleLine(
                        value,
                        SOURCE_REFERENCE_REVISION_FIELD,
                        AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                        MAX_REVISION_CHARS));
  }

  Map<String, Object> toJsonValue() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put(URL_FIELD, url.toString());
    revision.ifPresent(text -> value.put(REVISION_FIELD, text));
    return value;
  }

  static AppSubmissionSourceReference fromJsonValue(Object value) {
    Map<String, Object> object = AppSubmissionJson.requireObject(value, SOURCE_REFERENCE_FIELD);
    return new AppSubmissionSourceReference(
        parseUri(AppSubmissionJson.requireString(object, URL_FIELD, SOURCE_REFERENCE_URL_FIELD)),
        AppSubmissionJson.optionalString(object, REVISION_FIELD, SOURCE_REFERENCE_REVISION_FIELD));
  }

  private static URI parseUri(String rawUri) {
    try {
      return new URI(rawUri);
    } catch (URISyntaxException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid " + SOURCE_REFERENCE_URL_FIELD,
          exception);
    }
  }

  private static URI requirePublicUri(URI uri) {
    URI normalized = uri.normalize();
    if (!normalized.isAbsolute()) {
      throw AppCatalogSidecars.invalidEntry(SOURCE_REFERENCE_URL_FIELD + " must be absolute");
    }
    if (normalized.getUserInfo() != null || normalized.getFragment() != null) {
      throw AppCatalogSidecars.invalidEntry(
          SOURCE_REFERENCE_URL_FIELD + " must not include user info or fragment");
    }
    String scheme = normalized.getScheme().toLowerCase(java.util.Locale.ROOT);
    if (!scheme.equals("https") && !scheme.equals("http") && !scheme.equals("crypta")) {
      throw AppCatalogSidecars.invalidEntry(
          SOURCE_REFERENCE_URL_FIELD + " must use https, http, or crypta");
    }
    if ((scheme.equals("https") || scheme.equals("http")) && !hasPublicHttpHost(normalized)) {
      throw AppCatalogSidecars.invalidEntry(
          SOURCE_REFERENCE_URL_FIELD + " must include a public host");
    }
    if (scheme.equals("crypta")
        && AppSubmissionRedactionScanner.containsPrivateInsertUriMaterial(normalized.toString())) {
      throw AppCatalogSidecars.invalidEntry(
          SOURCE_REFERENCE_URL_FIELD + " must not contain private insert URI");
    }
    return normalized;
  }

  private static boolean hasPublicHttpHost(URI uri) {
    String host = uri.getHost();
    if (host == null || host.isBlank()) {
      return false;
    }
    String normalized = canonicalHttpHost(host);
    if (normalized.isBlank()) {
      return false;
    }
    return !isLocalHostName(normalized)
        && !isNonPublicIpv4Literal(normalized)
        && !isNonPublicIpv6Literal(normalized);
  }

  private static String canonicalHttpHost(String host) {
    String normalized = stripIpv6Brackets(host.toLowerCase(Locale.ROOT));
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized;
  }

  private static boolean isLocalHostName(String host) {
    return "localhost".equals(host) || host.endsWith(".localhost");
  }

  private static String stripIpv6Brackets(String host) {
    if (host.length() >= 2 && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
      return host.substring(1, host.length() - 1);
    }
    return host;
  }

  private static boolean isNonPublicIpv4Literal(String host) {
    int[] octets = parseIpv4AddressLiteral(host);
    if (octets.length == 0) {
      return false;
    }
    return isNonPublicIpv4Octets(octets);
  }

  private static int[] parseIpv4AddressLiteral(String host) {
    return parseIpv4AddressParts(host)
        .flatMap(AppSubmissionSourceReference::packIpv4Address)
        .map(AppSubmissionSourceReference::ipv4AddressOctets)
        .orElseGet(AppSubmissionSourceReference::emptyIpv4Octets);
  }

  private static Optional<long[]> parseIpv4AddressParts(String host) {
    String[] parts = host.split("\\.", -1);
    if (parts.length < 1 || parts.length > 4) {
      return Optional.empty();
    }
    long[] values = new long[parts.length];
    for (int index = 0; index < parts.length; index++) {
      Optional<Long> parsed = parseIpv4AddressPart(parts[index]);
      if (parsed.isEmpty()) {
        return Optional.empty();
      }
      values[index] = parsed.orElseThrow();
    }
    return Optional.of(values);
  }

  private static Optional<Long> packIpv4Address(long[] values) {
    return switch (values.length) {
      case 1 -> packIpv4Address(values, new long[] {0xFFFF_FFFFL}, new int[] {0});
      case 2 -> packIpv4Address(values, new long[] {0xFFL, 0xFF_FFFFL}, new int[] {24, 0});
      case 3 -> packIpv4Address(values, new long[] {0xFFL, 0xFFL, 0xFFFFL}, new int[] {24, 16, 0});
      case 4 ->
          packIpv4Address(
              values, new long[] {0xFFL, 0xFFL, 0xFFL, 0xFFL}, new int[] {24, 16, 8, 0});
      default -> Optional.empty();
    };
  }

  private static Optional<Long> packIpv4Address(long[] values, long[] limits, int[] shifts) {
    long address = 0L;
    for (int index = 0; index < values.length; index++) {
      if (values[index] > limits[index]) {
        return Optional.empty();
      }
      address |= values[index] << shifts[index];
    }
    return Optional.of(address);
  }

  private static int[] ipv4AddressOctets(long address) {
    return new int[] {
      (int) ((address >>> 24) & 0xFF),
      (int) ((address >>> 16) & 0xFF),
      (int) ((address >>> 8) & 0xFF),
      (int) (address & 0xFF)
    };
  }

  private static int[] emptyIpv4Octets() {
    return new int[0];
  }

  private static Optional<Long> parseIpv4AddressPart(String part) {
    if (part.isEmpty()) {
      return Optional.empty();
    }
    int radix = 10;
    String digits = part;
    if (digits.startsWith("0x") || digits.startsWith("0X")) {
      radix = 16;
      digits = digits.substring(2);
    } else if (digits.length() > 1 && digits.startsWith("0")) {
      radix = 8;
      digits = digits.substring(1);
    }
    if (digits.isEmpty()) {
      return Optional.empty();
    }
    long value = 0L;
    for (int index = 0; index < digits.length(); index++) {
      int digit = Character.digit(digits.charAt(index), radix);
      if (digit < 0) {
        return Optional.empty();
      }
      value = value * radix + digit;
      if (value > 0xFFFF_FFFFL) {
        return Optional.empty();
      }
    }
    return Optional.of(value);
  }

  private static boolean isNonPublicIpv6Literal(String host) {
    if (!host.contains(":")) {
      return false;
    }
    try {
      InetAddress address = InetAddress.getByName(host);
      if (address instanceof Inet4Address ipv4Address) {
        return isNonPublicIpv4AddressBytes(ipv4Address.getAddress());
      }
      if (address instanceof Inet6Address ipv6Address) {
        return isNonPublicIpv6Address(ipv6Address);
      }
      return true;
    } catch (UnknownHostException _) {
      return true;
    }
  }

  private static boolean isNonPublicIpv6Address(Inet6Address address) {
    byte[] bytes = address.getAddress();
    if (address.isAnyLocalAddress()
        || address.isLoopbackAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return true;
    }
    int firstByte = bytes[0] & 0xFF;
    if ((firstByte & 0xFE) == 0xFC) {
      return true;
    }
    Optional<int[]> embeddedIpv4 = embeddedIpv4Address(bytes);
    return embeddedIpv4.isPresent() && isNonPublicIpv4Octets(embeddedIpv4.orElseThrow());
  }

  private static Optional<int[]> embeddedIpv4Address(byte[] bytes) {
    boolean hasIpv4MappedPrefix = true;
    for (int index = 0; index < 10; index++) {
      if (bytes[index] != 0) {
        hasIpv4MappedPrefix = false;
        break;
      }
    }
    if (hasIpv4MappedPrefix && bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF) {
      return Optional.of(lastFourBytesAsOctets(bytes));
    }
    boolean hasIpv4CompatiblePrefix = true;
    for (int index = 0; index < 12; index++) {
      if (bytes[index] != 0) {
        hasIpv4CompatiblePrefix = false;
        break;
      }
    }
    if (hasIpv4CompatiblePrefix) {
      return Optional.of(lastFourBytesAsOctets(bytes));
    }
    return Optional.empty();
  }

  private static int[] lastFourBytesAsOctets(byte[] bytes) {
    return new int[] {bytes[12] & 0xFF, bytes[13] & 0xFF, bytes[14] & 0xFF, bytes[15] & 0xFF};
  }

  private static boolean isNonPublicIpv4AddressBytes(byte[] bytes) {
    return isNonPublicIpv4Octets(
        new int[] {bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF, bytes[3] & 0xFF});
  }

  private static boolean isNonPublicIpv4Octets(int[] octets) {
    int first = octets[0];
    int second = octets[1];
    return first == 0
        || first == 10
        || first == 127
        || (first == 169 && second == 254)
        || (first == 172 && second >= 16 && second <= 31)
        || (first == 192 && second == 168)
        || (first == 100 && second >= 64 && second <= 127)
        || first >= 224;
  }
}
