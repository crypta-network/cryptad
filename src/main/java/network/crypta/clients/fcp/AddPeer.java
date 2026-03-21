package network.crypta.clients.fcp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.keys.FreenetURI;
import network.crypta.node.RequestStarter;
import network.crypta.runtime.spi.PeerAddFailureReason;
import network.crypta.runtime.spi.PeerAddRejectedException;
import network.crypta.runtime.spi.PeerFieldSet;
import network.crypta.runtime.spi.PeerSnapshot;
import network.crypta.runtime.spi.PeerTrust;
import network.crypta.runtime.spi.PeerVisibility;
import network.crypta.support.MediaType;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.Bucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * FCP message that adds a new peer reference to the running node.
 *
 * <p>Instances of this class are constructed from a {@link SimpleFieldSet} received over an FCP
 * connection. The constructor parses common metadata such as {@code Identifier}, {@code Trust}, and
 * {@code Visibility}, and, when present, the peer reference itself or an indirection to it using a
 * {@code URL} or {@code File} field. During {@link #run(FCPConnectionHandler)} the message resolves
 * the reference, validates that it is well-formed and not a self reference, and finally installs
 * the new peer in the node's darknet or opennet peer table.
 *
 * <p>The implementation enforces full-access permissions, rejects duplicate peers, and translates
 * low-level parsing or network errors into {@link MessageInvalidException} instances that are
 * reported back to the client as protocol errors. AddPeer instances are not thread-safe and are
 * intended to be used only within the {@link FCPConnectionHandler} that is currently processing the
 * corresponding FCP connection.
 *
 * <p>Typical callers do not construct this class directly; instead they delegate to {@link
 * FCPMessage#create(String, SimpleFieldSet)} after decoding the message name and fields from the
 * wire.
 */
public final class AddPeer extends FCPMessage {
  private static final Logger LOG = LoggerFactory.getLogger(AddPeer.class);

  /**
   * Protocol message name constant for {@code AddPeer}.
   *
   * <p>FCP clients send this value as the textual message name when requesting that the node add a
   * new peer reference, and the server uses it when selecting {@link AddPeer} from {@link
   * FCPMessage#create(String, SimpleFieldSet)} while decoding inbound messages.
   */
  public static final String NAME = "AddPeer";

  SimpleFieldSet fs;
  final String messageIdentifier;
  final PeerTrust trust;
  final PeerVisibility visibility;

  /**
   * Creates a new {@link AddPeer} instance from the supplied field set.
   *
   * <p>The constructor extracts the {@code Identifier}, {@code Trust}, and {@code Visibility}
   * fields from {@code fs}, storing the identifier for later replies and converting the trust and
   * visibility strings to the corresponding {@link PeerTrust} and {@link PeerVisibility}
   * enumeration values. The extracted keys are removed from the field set so that the remaining
   * data describes only the peer reference itself or indirections to it such as {@code URL} and
   * {@code File} fields.
   *
   * <p>No I/O is performed at construction time. Any issues with missing or invalid fields are
   * reported immediately via {@link MessageInvalidException}, allowing callers to send a clear
   * protocol error back to the client before attempting to interact with the node.
   *
   * @param fs client-supplied field set containing the decoded AddPeer request fields, including
   *     identifier, trust, visibility, and peer reference information; must not be {@code null}
   * @throws MessageInvalidException if required fields are missing, empty, or cannot be converted
   *     into valid {@link PeerTrust} or {@link PeerVisibility} values
   */
  public AddPeer(SimpleFieldSet fs) throws MessageInvalidException {
    this.fs = fs;
    this.messageIdentifier = fs.get("Identifier");
    fs.removeValue("Identifier");

    String trustValue = fs.get("Trust");
    if (trustValue == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "AddPeer requires Trust", messageIdentifier, false);
    }
    try {
      this.trust = PeerTrust.valueOf(trustValue);
      fs.removeValue("Trust");
    } catch (IllegalArgumentException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Invalid Trust value on AddPeer",
          messageIdentifier,
          false);
    }

    String visibilityValue = fs.get("Visibility");
    if (visibilityValue == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "AddPeer requires Visibility",
          messageIdentifier,
          false);
    }
    try {
      this.visibility = PeerVisibility.valueOf(visibilityValue);
      fs.removeValue("Visibility");
    } catch (IllegalArgumentException _) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Invalid Visibility value on AddPeer",
          messageIdentifier,
          false);
    }
  }

  /**
   * Returns the field set used when serializing this message to the wire.
   *
   * <p>This implementation returns a new, initially empty {@link SimpleFieldSet} instance with the
   * appropriate structural flags. As a consequence, outbound AddPeer messages contain only the
   * protocol message name without additional fields. Server-side processing instead relies on the
   * constructor-supplied field set stored in the {@link #fs} field when handling incoming messages.
   *
   * @return a new, empty {@link SimpleFieldSet} that results in a minimal on-the-wire
   *     representation when {@link #send(java.io.OutputStream)} is invoked
   */
  @Override
  public SimpleFieldSet getFieldSet() {
    return new SimpleFieldSet(true);
  }

  /**
   * Returns the FCP message name for this type.
   *
   * <p>The returned value is always {@link #NAME}. It is written as the first line of the
   * serialized message output and is also consulted by {@link FCPMessage#create(String,
   * SimpleFieldSet)} when mapping inbound messages to concrete implementations such as {@link
   * AddPeer}.
   *
   * @return non-{@code null} message name token identifying the AddPeer request type on the wire
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Fetches a peer reference document from the given URL.
   *
   * <p>This helper opens a {@link URLConnection}, selects an appropriate character set using {@link
   * MediaType#getCharsetRobustOrUTF(String)} based on the {@code Content-Type} header, and reads
   * the entire response as text. Lines are appended to a {@link StringBuilder} in order with single
   * {@code '\n'} separators, producing a form that can later be parsed into a {@link
   * SimpleFieldSet} representation of the peer reference.
   *
   * <p>The connection's input stream is closed automatically when the method returns, but the
   * {@link URLConnection} itself is not further configured (for example, no timeouts are changed).
   * Callers are expected to provide a URL that yields a small text document containing the desired
   * reference.
   *
   * @param url absolute URL pointing to a textual peer reference document; must not be {@code null}
   * @return mutable buffer containing the full textual contents of the response, including trailing
   *     newline characters if present
   * @throws IOException if establishing the connection or reading the response body fails for any
   *     reason, including network errors or unexpected end-of-stream conditions
   */
  public static StringBuilder getReferenceFromURL(URL url) throws IOException {
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
   * Fetches a peer reference document from a {@link FreenetURI}.
   *
   * <p>The supplied {@link HighLevelSimpleClient} is used to request up to approximately
   * 31&nbsp;000 bytes of data from the given URI. The response is exposed as a {@link Bucket}, from
   * which this method opens an input stream and reads the contents as text using {@link
   * MediaType#getCharsetRobustOrUTF(String)} with a {@code text/plain} content type hint. Each line
   * of text is appended to a {@link StringBuilder} with a single {@code '\n'} separator, producing
   * a buffer suitable for later parsing into a {@link SimpleFieldSet}.
   *
   * <p>The client instance is not closed or modified by this method; callers remain responsible for
   * its lifecycle and any broader request management. This helper focuses purely on efficiently
   * retrieving small textual reference documents.
   *
   * @param url Freenet URI locating the remotely stored peer reference document; must not be {@code
   *     null}
   * @param client high-level client instance used to perform the fetch within the appropriate
   *     request priority class and security context; must be configured for the target node
   * @return mutable buffer containing the full textual contents of the fetched document, including
   *     any trailing newline characters
   * @throws IOException if reading the fetched data from the node fails due to I/O errors in the
   *     underlying stream
   * @throws FetchException if the URI cannot be fetched successfully, for example, due to routing
   *     failures, timeouts, or protocol-level error responses
   */
  public static StringBuilder getReferenceFromFreenetURI(
      FreenetURI url, HighLevelSimpleClient client) throws IOException, FetchException {
    StringBuilder ref = new StringBuilder(1024); // the 1024 is the initial capacity

    try (Bucket bucket = client.fetch(url, 31000).asBucket();
        // limit to 31k, which should suffice even if we add many more ipv6 addresses
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

  /**
   * Executes the AddPeer request against the supplied node.
   *
   * <p>The method first enforces that the originating FCP connection has full-access permissions,
   * rejecting the request with {@link ProtocolErrorMessage#ACCESS_DENIED} when the handler lacks
   * the required capabilities. It then resolves the peer reference from the constructor-supplied
   * field set, optionally dereferencing a {@code URL} or {@code File} indirection, and parses the
   * resulting text into a structured {@link SimpleFieldSet}.
   *
   * <p>Depending on whether the {@code opennet} flag is present, the implementation forwards the
   * resolved reference to the runtime peer-management port, which performs peer creation,
   * validation, self-checking, and registration with the node. Any parse errors, signature
   * problems, duplicate identities, or configuration constraints are reported via {@link
   * MessageInvalidException} with an appropriate {@link ProtocolErrorMessage} code, which the
   * handler will translate into a protocol error response.
   *
   * @param handler connection handler representing the client session that issued the AddPeer
   *     request; used to send back the resulting {@link PeerMessage} or error messages
   * @throws MessageInvalidException if access is denied, the peer reference cannot be parsed or
   *     verified, the reference describes the node itself, or a peer with the same identity already
   *     exists on the node
   */
  @Override
  public void run(FCPConnectionHandler handler) throws MessageInvalidException {
    ensureFullAccess(handler);
    fs = resolveFieldSetForReference(handler);
    try {
      PeerSnapshot snapshot =
          handler.getServer().runtime().peer().add(toPeerFieldSet(fs), trust, visibility);
      handler.send(new PeerMessage(snapshot, messageIdentifier));
    } catch (PeerAddRejectedException e) {
      throw new MessageInvalidException(
          protocolCodeFor(e.reason()), e.getMessage(), messageIdentifier, false);
    }
  }

  private void ensureFullAccess(FCPConnectionHandler handler) throws MessageInvalidException {
    if (!handler.hasFullAccess()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "AddPeer requires full access",
          messageIdentifier,
          false);
    }
  }

  private SimpleFieldSet resolveFieldSetForReference(FCPConnectionHandler handler)
      throws MessageInvalidException {
    String urlString = fs.get("URL");
    if (urlString != null) {
      return buildFieldSetFromUrl(urlString, handler);
    }
    String fileString = fs.get("File");
    if (fileString != null) {
      return buildFieldSetFromFile(fileString);
    }
    return fs;
  }

  private SimpleFieldSet buildFieldSetFromUrl(String urlString, FCPConnectionHandler handler)
      throws MessageInvalidException {
    StringBuilder ref = fetchReferenceFromUrl(urlString, handler);
    String refString = ref.toString().trim();
    if (refString.isEmpty()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.REF_PARSE_ERROR,
          "Error parsing ref from URL <" + urlString + '>',
          messageIdentifier,
          false);
    }
    try {
      return new SimpleFieldSet(refString, false, true, true);
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.REF_PARSE_ERROR,
          "Error parsing ref from URL <" + urlString + ">: " + e.getMessage(),
          messageIdentifier,
          false);
    }
  }

  private StringBuilder fetchReferenceFromUrl(String urlString, FCPConnectionHandler handler)
      throws MessageInvalidException {
    try {
      return tryFetchFromCryptaUriOrUrl(urlString, handler);
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.URL_PARSE_ERROR,
          "Error parsing ref URL <" + urlString + ">: " + e.getMessage(),
          messageIdentifier,
          false);
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.URL_PARSE_ERROR,
          "IO error while retrieving ref URL <" + urlString + ">: " + e.getMessage(),
          messageIdentifier,
          false);
    }
  }

  private StringBuilder tryFetchFromCryptaUriOrUrl(String urlString, FCPConnectionHandler handler)
      throws IOException {
    try {
      FreenetURI refUri = new FreenetURI(urlString);
      HighLevelSimpleClient client =
          handler
              .getServer()
              .messageRuntimeSupport()
              .makeClient(RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS, true, true);
      return AddPeer.getReferenceFromFreenetURI(refUri, client);
    } catch (MalformedURLException | FetchException _) {
      LOG.warn("Url cannot be used as Crypta URI, trying to fetch as URL: {}", urlString);
      URL url = createUrlFromString(urlString);
      return AddPeer.getReferenceFromURL(url);
    }
  }

  private URL createUrlFromString(String urlString) throws MalformedURLException {
    try {
      return URI.create(urlString).toURL();
    } catch (IllegalArgumentException uriException) {
      throw new MalformedURLException(uriException.getMessage());
    }
  }

  private SimpleFieldSet buildFieldSetFromFile(String fileString) throws MessageInvalidException {
    StringBuilder ref = readReferenceFromFile(fileString);
    String refString = ref.toString().trim();
    if (refString.isEmpty()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.REF_PARSE_ERROR,
          "Error parsing ref from file <" + fileString + '>',
          messageIdentifier,
          false);
    }
    try {
      return new SimpleFieldSet(refString, false, true, true);
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.REF_PARSE_ERROR,
          "Error parsing ref from file <" + fileString + ">: " + e.getMessage(),
          messageIdentifier,
          false);
    }
  }

  private StringBuilder readReferenceFromFile(String fileString) throws MessageInvalidException {
    File file = new File(fileString);
    if (!file.isFile()) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.NOT_A_FILE_ERROR,
          "The given ref file path <" + fileString + "> is not a file",
          messageIdentifier,
          false);
    }
    StringBuilder ref = new StringBuilder(1024);
    try (BufferedReader in =
        new BufferedReader(
            new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8))) {
      String line;
      while ((line = in.readLine()) != null) {
        ref.append(line.trim()).append('\n');
      }
      return ref;
    } catch (FileNotFoundException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FILE_NOT_FOUND,
          "File not found when retrieving ref file <" + fileString + ">: " + e.getMessage(),
          messageIdentifier,
          false);
    } catch (IOException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FILE_PARSE_ERROR,
          "IO error while retrieving ref file <" + fileString + ">: " + e.getMessage(),
          messageIdentifier,
          false);
    }
  }

  private static PeerFieldSet toPeerFieldSet(SimpleFieldSet fieldSet) {
    if (fieldSet.isEmpty()) {
      return PeerFieldSet.empty();
    }

    LinkedHashMap<String, String> directValues = new LinkedHashMap<>(fieldSet.directKeyValues());
    LinkedHashMap<String, PeerFieldSet> directSubsets = new LinkedHashMap<>();
    for (Map.Entry<String, SimpleFieldSet> entry : fieldSet.directSubsets().entrySet()) {
      PeerFieldSet subset = toPeerFieldSet(entry.getValue());
      if (!subset.isEmpty()) {
        directSubsets.put(entry.getKey(), subset);
      }
    }
    return new PeerFieldSet(directValues, directSubsets);
  }

  private static int protocolCodeFor(PeerAddFailureReason reason) {
    return switch (reason) {
      case REF_PARSE_ERROR -> ProtocolErrorMessage.REF_PARSE_ERROR;
      case OPENNET_DISABLED -> ProtocolErrorMessage.OPENNET_DISABLED;
      case REF_SIGNATURE_INVALID -> ProtocolErrorMessage.REF_SIGNATURE_INVALID;
      case CANNOT_PEER_WITH_SELF -> ProtocolErrorMessage.CANNOT_PEER_WITH_SELF;
      case DUPLICATE_PEER_REF -> ProtocolErrorMessage.DUPLICATE_PEER_REF;
    };
  }
}
