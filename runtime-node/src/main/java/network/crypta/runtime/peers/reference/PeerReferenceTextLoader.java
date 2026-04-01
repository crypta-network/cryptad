package network.crypta.runtime.peers.reference;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.support.MediaType;
import network.crypta.support.api.Bucket;

/**
 * Loads peer-reference text from URL or Freenet URI sources.
 *
 * <p>This helper centralizes the small amount of I/O needed by peer-add workflows when the noderef
 * itself is not embedded in the original request. HTTP toadlets, text-mode endpoints, and FCP
 * compatibility layers can all call the same runtime-owned API instead of importing one another's
 * transport-specific helpers.
 *
 * <p>The implementation is intentionally narrow. It preserves the legacy charset selection,
 * line-by-line reading, and newline-joining behavior that existing noderef parsing code expects.
 * The methods return a mutable {@link StringBuilder} so callers can keep their current parsing and
 * compatibility code paths with minimal churn while this seam is being decoupled.
 */
public final class PeerReferenceTextLoader {
  private PeerReferenceTextLoader() {}

  /**
   * Reads peer-reference text from a regular URL.
   *
   * <p>The method opens the supplied URL, inspects the response content type, and selects the same
   * effective charset resolution path used by the historical loader. It then reads the response one
   * line at a time and appends a single {@code '\n'} after each line. This preserves the text shape
   * expected by downstream noderef parsers, including a trailing newline for non-empty final lines.
   *
   * @param url absolute URL pointing at a textual peer-reference document that is small enough to
   *     read into memory in one pass
   * @return mutable buffer containing the fetched peer-reference text with one newline appended
   *     after each source line
   * @throws IOException if opening the connection or reading the response body fails for any reason
   *     exposed by the underlying stream or URL implementation
   */
  public static StringBuilder readFromUrl(URL url) throws IOException {
    StringBuilder ref = new StringBuilder(1024);

    URLConnection uc = url.openConnection();
    try (InputStream is = uc.getInputStream();
        BufferedReader in =
            new BufferedReader(
                new InputStreamReader(is, MediaType.getCharsetRobustOrUTF(uc.getContentType())))) {

      String line;
      while ((line = in.readLine()) != null) {
        ref.append(line).append('\n');
      }
      return ref;
    }
  }

  /**
   * Reads peer-reference text from a Freenet URI.
   *
   * <p>The supplied client performs the historical {@code client.fetch(uri, 31000)} call so the
   * loader remains behaviorally identical to the code it replaces. The fetched bucket is then read
   * as plain text, again appending a single {@code '\n'} after each line so callers receive the
   * same normalized noderef text shape as the URL-based variant.
   *
   * @param uri Freenet URI that identifies the stored peer-reference document to fetch from the
   *     node network
   * @param client high-level client used to execute the fetch within the caller's existing runtime
   *     configuration and request policy
   * @return mutable buffer containing the fetched peer-reference text with one newline appended
   *     after each source line
   * @throws IOException if the fetch succeeds but the returned bucket cannot be read completely as
   *     text
   * @throws FetchException if the client cannot fetch the URI successfully, including timeout,
   *     routing, or protocol-level failures reported by the fetch path
   */
  public static StringBuilder readFromFreenetUri(FreenetURI uri, HighLevelSimpleClient client)
      throws IOException, FetchException {
    StringBuilder ref = new StringBuilder(1024);

    try (Bucket bucket = client.fetch(uri, 31000).asBucket();
        InputStream is = bucket.getInputStream();
        BufferedReader in =
            new BufferedReader(
                new InputStreamReader(is, MediaType.getCharsetRobustOrUTF("text/plain")))) {

      String line;
      while ((line = in.readLine()) != null) {
        ref.append(line).append('\n');
      }
      return ref;
    }
  }
}
