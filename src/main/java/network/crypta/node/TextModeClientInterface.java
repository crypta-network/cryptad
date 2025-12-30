package network.crypta.node;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.Set;
import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.DumperSnoopMetadata;
import network.crypta.client.events.EventDumper;
import network.crypta.client.filter.ContentFilter;
import network.crypta.clients.fcp.AddPeer;
import network.crypta.crypt.RandomSource;
import network.crypta.fs.AppEnv;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.node.DarknetPeerNode.FRIEND_TRUST;
import network.crypta.node.DarknetPeerNode.FRIEND_VISIBILITY;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SizeUtil;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Text‑mode console interface for interacting with a running node.
 *
 * <p>This component reads line‑oriented commands from an {@code InputStream}, executes them using
 * the node's high‑level client APIs, and writes human‑readable results to an {@code OutputStream}.
 * It is intended for scripting, quick diagnostics, and environments where a graphical UI is not
 * available. The interface supports fetching and inserting content, managing peers, inspecting
 * memory and system information, and loading or unloading plugins. Commands are deliberately
 * conservative: operations that might affect the terminal (for example, output containing escape
 * sequences) are guarded to reduce the risk of unintended terminal control.
 *
 * <p>Lifecycle and concurrency: instances are designed to be used by a single thread. The class
 * implements {@code Runnable}; typical usage creates an instance and executes it on a background
 * thread while the caller feeds input and consumes output. The object maintains minimal mutable
 * state; most operations delegate to existing node services which perform the actual work and I/O.
 * Log statements are emitted for visibility but do not alter behavior.
 *
 * <ul>
 *   <li>Responsibilities: parse commands, invoke node/client operations, and format responses.
 *   <li>Notable behaviors: avoids printing large payloads to the terminal and warns on content that
 *       appears to contain terminal control characters.
 *   <li>Typical pattern: prompt → read command → execute → write result → continue until QUIT.
 * </ul>
 *
 * @author amphibian
 * @see Runnable
 */
public class TextModeClientInterface implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(TextModeClientInterface.class);

  private static final String LOG_CAUGHT = "Caught {}";
  private static final String PEER_IDENTITY_SUFFIX = " identity\r\n";
  private static final String PEER_IP_NAME_IDENTITY_SUFFIX = " ip+port, name, or identity\r\n";
  private static final String LOG_KEY_LITERAL = "Key: {}";
  private static final String MALFORMED_URI_LITERAL = "Malformed URI: ";
  private static final String CONTENT_MIME_LITERAL = "Content MIME type: ";
  private static final String ESCAPE_WARNING_SUFFIX =
      " commands! Save it to a file if you must with GETFILE:";
  private static final String ERROR_PREFIX = "Error: ";
  private static final String REDIRECT_PREFIX = "Permanent redirect: ";
  private static final String ESCAPE_WARNING_PREFIX =
      "Data may contain escape codes which could cause the terminal to run arbitrary";
  private static final String URI_WOULD_HAVE_BEEN = "URI would have been: ";
  private static final String URI_PREFIX = "URI: ";
  private static final String FINISHED_INSERT_BUT = "Finished insert but: ";
  private static final String NO_PEER_FOR_PREFIX = "no peer for ";
  private static final String PEER_DETAILS_FAIL_PREFIX =
      "n.getPeerNode() failed to get peer details for ";
  private static final String CRLF2 = "\r\n\r\n";
  private static final String DID_NOT_PARSE_LITERAL = "Did not parse: {}";
  private static final String FILTER_BASE_URL = "http://127.0.0.1:8888/";
  private static final String PLUGLOAD_HELP =
      """
        PLUGLOAD:O: pluginName         - Load official plugin from freenetproject.org\r
        PLUGLOAD:F: file://<filename>  - Load plugin from file\r
        PLUGLOAD:U: http://...         - Load plugin from online file\r
        PLUGLOAD:K: freenet key        - Load plugin from freenet uri\r
      """;

  final RandomSource r;
  final Node n;
  final NodeClientCore core;
  final HighLevelSimpleClient client;
  final File downloadsDir;
  final InputStream in;
  final Writer w;
  private static final Charset ENCODING = StandardCharsets.UTF_8;

  @FunctionalInterface
  private interface CommandHandler {
    boolean handle(String line, String uline, BufferedReader reader, StringBuilder outsb)
        throws IOException;
  }

  private final HashMap<String, CommandHandler> handlers = new HashMap<>();

  private static final Set<String> ALLOW_BARE_TOKENS =
      Set.of(
          "HELP",
          "STATUS",
          "MEMSTAT",
          "SHUTDOWN",
          "RESTART",
          "QUIT",
          "PEERS",
          "BLOW",
          "UPDATE",
          "MAKESSK",
          "PLUGLIST",
          "PLUGLOAD",
          "ANNOUNCE");

  private static String commandToken(String uline) {
    int idx = uline.indexOf(':');
    if (idx >= 0) return uline.substring(0, idx);
    String bare = uline.trim();
    return ALLOW_BARE_TOKENS.contains(bare) ? bare : "";
  }

  /**
   * Create a text‑mode interface bound to a server context.
   *
   * <p>This convenience constructor extracts the required node services from the provided server
   * and wires a client with interactive priority. It attaches an event dumper to the supplied
   * output so that asynchronous client events are visible to the user while commands are processed.
   * The instance reads commands from {@code in} and writes responses to {@code out} using UTF‑8.
   *
   * @param server the server wrapper providing the node, client core, randomness and download
   *     directory; must be non‑null and fully initialized before invocation.
   * @param in the byte stream to read TMCI commands from; the caller owns its lifecycle and must
   *     provide data in UTF‑8 compatible encoding.
   * @param out the byte stream to write human‑readable responses to; remains open after method
   *     returns and is not closed by the constructor.
   */
  public TextModeClientInterface(
      TextModeClientInterfaceServer server, InputStream in, OutputStream out) {
    this.n = server.n;
    this.core = server.n.getClientCore();
    this.r = server.r;
    client = core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, false);
    this.downloadsDir = server.downloadsDir;
    this.in = in;
    this.w = new OutputStreamWriter(out, ENCODING);
    client.addEventHook(
        new EventDumper(new BufferedWriter(new OutputStreamWriter(out, ENCODING)), false));
    initHandlers();
  }

  /**
   * Create a text‑mode interface from explicit node components.
   *
   * <p>Use this form when the caller already holds references to the node, its client core, and a
   * preconfigured high‑level client. The instance streams commands from {@code in} and results to
   * {@code out}. The provided {@code downloadDir} is used when commands persist fetched content to
   * disk. No threads are started by the constructor; the caller should invoke {@link #run()} or
   * {@link #realRun()} on an appropriate thread to begin processing.
   *
   * @param n the running node instance backing all operations; must not be {@code null}.
   * @param core the client core associated with the node; used for request context and storage.
   * @param c a high‑level simple client to perform fetch/insert operations; expected to be
   *     configured for interactive use.
   * @param downloadDir directory to place files written by commands; must be writable by the
   *     process and may be relative or absolute.
   * @param in the input stream supplying commands; read using UTF‑8 compatible bytes.
   * @param out the output stream receiving responses and event logs; left open by this instance.
   */
  public TextModeClientInterface(
      Node n,
      NodeClientCore core,
      HighLevelSimpleClient c,
      File downloadDir,
      InputStream in,
      OutputStream out) {
    this.n = n;
    this.r = n.getRandom();
    this.core = core;
    this.client = c;
    this.downloadsDir = downloadDir;
    this.in = in;
    this.w = new OutputStreamWriter(out, ENCODING);
    client.addEventHook(
        new EventDumper(new BufferedWriter(new OutputStreamWriter(out, ENCODING)), false));
    initHandlers();
  }

  private void initHandlers() {
    handlers.put("GET", this::handleGet);
    handlers.put("DUMP", this::handleDump);
    handlers.put("GETFILE", this::handleGetFile);
    handlers.put("UPDATE", this::handleUpdate);
    handlers.put("FILTER", this::handleFilter);
    handlers.put("BLOW", this::handleBlow);
    handlers.put("SHUTDOWN", this::handleShutdown);
    handlers.put("RESTART", this::handleRestart);
    handlers.put("QUIT", this::handleQuit);
    handlers.put("MEMSTAT", this::handleMemstat);
    handlers.put("HELP", this::handleHelp);
    handlers.put("PUT", this::handlePutOrGetChk);
    handlers.put("GETCHK", this::handlePutOrGetChk);
    handlers.put("PUTDIR", this::handlePutDirOrPutSSKDirOrGetCHKDir);
    handlers.put("PUTSSKDIR", this::handlePutDirOrPutSSKDirOrGetCHKDir);
    handlers.put("GETCHKDIR", this::handlePutDirOrPutSSKDirOrGetCHKDir);
    handlers.put("PUTFILE", this::handlePutFileOrGetCHKFile);
    handlers.put("GETCHKFILE", this::handlePutFileOrGetCHKFile);
    handlers.put("MAKESSK", this::handleMakeSSK);
    handlers.put("PUTSSK", this::handlePutSSK);
    handlers.put("STATUS", this::handleStatus);
    handlers.put("ADDPEER", this::handleAddPeerOrConnect);
    handlers.put("CONNECT", this::handleAddPeerOrConnect);
    handlers.put("NAME", this::handleName);
    handlers.put("DISABLEPEER", this::handleDisablePeerCmd);
    handlers.put("ENABLEPEER", this::handleEnablePeerCmd);
    handlers.put("SETPEERLISTENONLY", this::handleSetPeerListenOnly);
    handlers.put("UNSETPEERLISTENONLY", this::handleUnsetPeerListenOnly);
    handlers.put("HAVEPEER", this::handleHavePeerCmd);
    handlers.put("REMOVEPEER", this::handleRemovePeerOrDisconnect);
    handlers.put("DISCONNECT", this::handleRemovePeerOrDisconnect);
    handlers.put("PEER", this::handlePeer);
    handlers.put("PEERWMD", this::handlePeerWmd);
    handlers.put("PEERS", this::handlePeers);
    handlers.put("PLUGLOAD", this::handlePlugLoad);
    handlers.put("PLUGLIST", this::handlePlugList);
    handlers.put("PLUGKILL", this::handlePlugKill);
    handlers.put("ANNOUNCE", this::handleAnnounce);
  }

  @Override
  public void run() {
    try {
      realRun();
    } catch (IOException e) {
      if (LOG.isDebugEnabled()) LOG.debug(LOG_CAUGHT, e, e);
    } catch (Exception t) {
      LOG.error(LOG_CAUGHT, t, t);
    }
  }

  /**
   * Execute the TMCI read–execute–print loop until termination.
   *
   * <p>Writes an initial header, then repeatedly prompts, reads a single command, dispatches it to
   * the appropriate handler, and writes the response. The session ends when the input stream
   * closes, when a handler explicitly signals closure (for example, {@code QUIT}), or when an I/O
   * error occurs on the output stream. The method is blocking and intended to be called on a
   * dedicated thread.
   *
   * @throws IOException if writing the initial header fails or the prompt cannot be written due to
   *     an underlying I/O error on the output stream.
   */
  public void realRun() throws IOException {
    printHeader(w);

    BufferedReader reader = new BufferedReader(new InputStreamReader(in, ENCODING));
    while (true) {
      try {
        w.write("TMCI> ");
        w.flush();
        if (processLine(reader)) {
          reader.close();
          return;
        }
      } catch (SocketException e) {
        LOG.error("Socket error: {}", e, e);
        return;
      } catch (Exception t) {
        LOG.error(LOG_CAUGHT, t, t);
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        try {
          w.write(sw.toString());
        } catch (IOException e) {
          LOG.error("Socket error: {}", e, e);
          return;
        }
      }
    }
  }

  private void printHeader(Writer sw) throws IOException {
    StringBuilder sb = new StringBuilder();

    sb.append("Trivial Text Mode Client Interface\r\n");
    sb.append("---------------------------------------\r\n");
    sb.append("Crypta v")
        .append(Version.currentBuildNumber())
        .append("+")
        .append(Version.gitRevision())
        .append("\r\n");
    sb.append("Enter one of the following commands:\r\n");
    sb.append("GET:<Crypta key> - Fetch a key\r\n");
    sb.append("DUMP:<Crypta key> - Dump metadata for a key\r\n");
    sb.append(
        "PUT:\\r"
            + "\\n"
            + "<text, until a . on a line by itself> - Insert the document and return the"
            + " key.\r\n");
    sb.append("PUT:<text> - Put a single line of text to a CHK and return the key.\r\n");
    sb.append(
        "GETCHK:\\r"
            + "\\n"
            + "<text, until a . on a line by itself> - Get the key that would be returned if the"
            + " document was inserted.\r\n");
    sb.append("GETCHK:<text> - Get the key that would be returned if the line was inserted.\r\n");
    sb.append("PUTFILE:<filename>[#<mimetype>] - Put a file from disk.\r\n");
    sb.append(
        "GETFILE:<filename> - Fetch a key and put it in a file. If the key includes a filename we"
            + " will use it but we will not overwrite local files.\r\n");
    sb.append(
        "GETCHKFILE:<filename> - Get the key that would be returned if we inserted the file.\r\n");
    sb.append("PUTDIR:<path>[#<defaultfile>] - Put the entire directory from disk.\r\n");
    sb.append(
        "GETCHKDIR:<path>[#<defaultfile>] - Get the key that would be returned if we'd put the"
            + " entire directory from disk.\r\n");
    sb.append("MAKESSK - Create an SSK keypair.\r\n");
    sb.append(
        "PUTSSK:<insert uri>;<url to redirect to> - Insert an SSK redirect to a file already"
            + " inserted.\r\n");
    sb.append(
        "PUTSSKDIR:<insert uri>#<path>[#<defaultfile>] - Insert an entire directory to an"
            + " SSK.\r\n");
    sb.append("PLUGLOAD: - Load plugin. (use \"PLUGLOAD:?\" for more info)\r\n");
    sb.append("PLUGLIST - List all loaded plugins.\r\n");
    sb.append("PLUGKILL:<pluginID> - Unload the plugin with the given ID (see PLUGLIST).\r\n");
    sb.append("CONNECT:<filename|URL> - see ADDPEER:<filename|URL> below\r\n");
    sb.append("CONNECT:\\r\\n<noderef> - see ADDPEER:\\r\\n<noderef> below\r\n");
    sb.append("DISCONNECT:<ip:port|name> - see REMOVEPEER:<ip:port|name|identity> below\r\n");
    sb.append("ADDPEER:<filename|URL> - add a peer from its ref in a file/url.\r\n");
    sb.append(
        "ADDPEER:\\r"
            + "\\n"
            + "<noderef including an End on a line by itself> - add a peer by entering a noderef"
            + " directly.\r\n");
    sb.append(
        "DISABLEPEER:<ip:port|name|identity> - disable a peer by providing its ip+port, name, or"
            + PEER_IDENTITY_SUFFIX);
    sb.append(
        "ENABLEPEER:<ip:port|name|identity> - enable a peer by providing its ip+port, name, or"
            + PEER_IDENTITY_SUFFIX);
    sb.append(
        "SETPEERLISTENONLY:<ip:port|name|identity> - set ListenOnly on a peer by providing its"
            + PEER_IP_NAME_IDENTITY_SUFFIX);
    sb.append(
        "UNSETPEERLISTENONLY:<ip:port|name|identity> - unset ListenOnly on a peer by providing its"
            + PEER_IP_NAME_IDENTITY_SUFFIX);
    sb.append(
        "HAVEPEER:<ip:port|name|identity> - report true/false on having a peer by providing its"
            + PEER_IP_NAME_IDENTITY_SUFFIX);
    sb.append(
        "REMOVEPEER:<ip:port|name|identity> - remove a peer by providing its ip+port, name, or"
            + PEER_IDENTITY_SUFFIX);
    sb.append(
        "PEER:<ip:port|name|identity> - report the noderef of a peer (without metadata) by"
            + " providing its ip+port, name, or identity\r\n");
    sb.append(
        "PEERWMD:<ip:port|name|identity> - report the noderef of a peer (with metadata) by"
            + " providing its ip+port, name, or identity\r\n");
    sb.append(
        "PEERS - report tab delimited list of peers with name, ip+port, identity, location, status"
            + " and idle time in seconds\r\n");
    sb.append("NAME:<new node name> - change the node's name.\r\n");
    sb.append("UPDATE ask the node to self-update if possible. \r\n");
    sb.append(
        "FILTER: \\r"
            + "\\n"
            + "<text, until a . on a line by itself> - output the content as it returns from the"
            + " content filter\r\n");
    sb.append(
        "STATUS - display some status information on the node including its reference and"
            + " connections.\r\n");
    sb.append("MEMSTAT - display some memory usage related informations.\r\n");
    sb.append("SHUTDOWN - exit the program\r\n");
    sb.append("ANNOUNCE[:<location>] - announce to the specified location\r\n");
    if (n.isUsingWrapper()) sb.append("RESTART - restart the program\r\n");
    if (core != null && core.getEndpoints().getDirectTMCI() != this) {
      sb.append("QUIT - close the socket\r\n");
    }
    if (Node.isTestnetEnabled()) {
      sb.append("WARNING: TESTNET MODE ENABLED. YOU HAVE NO ANONYMITY.\r\n");
    }
    sw.write(sb.toString());
  }

  /**
   * Parse a URL string into a {@code URL} instance using {@code URI} rules.
   *
   * <p>This helper first creates a {@code URI} from the supplied specification to take advantage of
   * its stricter validation, then converts it to a {@code URL}. Invalid syntactic forms are wrapped
   * as {@code MalformedURLException} to match common caller expectations.
   *
   * @param spec the textual URL/URI specification to parse; leading and trailing whitespace are not
   *     trimmed and should be removed by the caller if unacceptable.
   * @return a {@code URL} representing the same location as the parsed {@code URI} value.
   * @throws MalformedURLException if the input cannot be parsed into a well‑formed URL or contains
   *     characters not permitted by the URL syntax.
   */
  private static URL parseUrl(String spec) throws MalformedURLException {
    try {
      return URI.create(spec).toURL();
    } catch (IllegalArgumentException e) {
      MalformedURLException malformed = new MalformedURLException("Invalid URL: " + spec);
      malformed.initCause(e);
      throw malformed;
    }
  }

  private boolean processLine(BufferedReader reader) throws IOException {
    String line;
    StringBuilder outsb = new StringBuilder();
    try {
      line = reader.readLine();
    } catch (IOException e) {
      outsb.append("Bye... (").append(e).append(')');
      LOG.warn("Bye... ({})", e, e);
      return true;
    }
    if (line == null) return true;
    String uline = line.toUpperCase();
    if (LOG.isDebugEnabled()) LOG.debug("Command: {}", line);
    String token = commandToken(uline);
    CommandHandler handler = handlers.get(token);
    if (handler != null) {
      boolean shouldClose = handler.handle(line, uline, reader, outsb);
      if (!outsb.isEmpty()) {
        outsb.append("\r\n");
        w.write(outsb.toString());
        w.flush();
      }
      return shouldClose;
    }
    if (!uline.isEmpty()) {
      printHeader(w);
      w.write("\r\n");
      w.flush();
    }
    return false;
  }

  // Command handlers
  /**
   * Handle the GET command.
   *
   * <p>The boolean return value in all handlers indicates whether the TMCI session should close
   * after processing the command. GET never closes the session, so this handler always returns
   * {@code false}. The annotation suppresses the static analysis warning about constant returns
   * because that behavior is intentional.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleGet(String line, String uline, BufferedReader reader, StringBuilder outsb)
      throws IOException {
    String key = line.substring("GET:".length()).trim();
    LOG.info(LOG_KEY_LITERAL, key);
    FreenetURI uri;
    try {
      uri = new FreenetURI(key);
      LOG.info(LOG_KEY_LITERAL, uri);
    } catch (MalformedURLException e2) {
      outsb.append(MALFORMED_URI_LITERAL).append(key).append(" : ").append(e2);
      return false;
    }
    try {
      FetchResult result = client.fetch(uri);
      ClientMetadata cm = result.getMetadata();
      outsb.append(CONTENT_MIME_LITERAL).append(cm.getMIMEType());
      Bucket data = result.asBucket();
      if (data.size() > 32 * 1024) {
        LOG.warn("Data is more than 32K: {}", data.size());
        outsb.append("Data is more than 32K: ").append(data.size());
        return false;
      }
      byte[] dataBytes = BucketTools.toByteArray(data);
      boolean evil = containsTerminalControlChars(dataBytes);
      if (evil) {
        LOG.warn(ESCAPE_WARNING_PREFIX + ESCAPE_WARNING_SUFFIX);
        outsb.append(ESCAPE_WARNING_PREFIX + ESCAPE_WARNING_SUFFIX);
        return false;
      }
      outsb.append("Data:\r\n");
      outsb.append(new String(dataBytes, ENCODING));
    } catch (FetchException e) {
      outsb.append(ERROR_PREFIX).append(e.getMessage()).append("\r\n");
      if ((e.getMode() == FetchExceptionMode.SPLITFILE_ERROR) && (e.errorCodes != null)) {
        outsb.append(e.errorCodes.toVerboseString());
      }
      if (e.newURI != null) outsb.append(REDIRECT_PREFIX).append(e.newURI).append("\r\n");
    }
    return false;
  }

  private static boolean containsTerminalControlChars(byte[] dataBytes) {
    // Restrict to sequences known to manipulate terminals: ESC (0x1B) and single-byte CSI (0x9B).
    for (byte b : dataBytes) {
      int ub = b & 0xFF;
      if (ub == 0x1B /* ESC */ || ub == 0x9B /* single-byte CSI */) {
        return true;
      }
    }
    return false;
  }

  private void appendResultData(FetchResult result, StringBuilder outsb) throws IOException {
    ClientMetadata cm = result.getMetadata();
    outsb.append(CONTENT_MIME_LITERAL).append(cm.getMIMEType());
    Bucket data = result.asBucket();
    if (data.size() > 32 * 1024) {
      LOG.warn("Data is more than 32K: {}", data.size());
      outsb.append("Data is more than 32K: ").append(data.size());
      return;
    }
    byte[] dataBytes = BucketTools.toByteArray(data);
    boolean evil = containsTerminalControlChars(dataBytes);
    if (evil) {
      LOG.warn(ESCAPE_WARNING_PREFIX + ESCAPE_WARNING_SUFFIX);
      outsb.append(ESCAPE_WARNING_PREFIX + ESCAPE_WARNING_SUFFIX);
      return;
    }
    outsb.append("Data:\r\n");
    outsb.append(new String(dataBytes, ENCODING));
  }

  /**
   * Handle the DUMP command.
   *
   * <p>Like other TMCI handlers, the boolean return indicates whether the session should close
   * after processing. DUMP never closes the session, so it intentionally always returns {@code
   * false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleDump(String line, String uline, BufferedReader reader, StringBuilder outsb)
      throws IOException {
    String key = line.substring("DUMP:".length()).trim();
    LOG.info(LOG_KEY_LITERAL, key);
    FreenetURI uri;
    try {
      uri = new FreenetURI(key);
      LOG.info(LOG_KEY_LITERAL, uri);
    } catch (MalformedURLException e2) {
      outsb.append(MALFORMED_URI_LITERAL).append(key).append(" : ").append(e2);
      return false;
    }
    try {
      FetchContext context = client.getFetchContext();
      FetchWaiter fw = new FetchWaiter((RequestClient) client);
      ClientGetter get =
          new ClientGetter(
              fw, uri, context, RequestStarter.INTERACTIVE_PRIORITY_CLASS, null, null, null);
      get.setMetaSnoop(new DumperSnoopMetadata());
      get.start(n.getClientCore().getClientContext());
      FetchResult result = fw.waitForCompletion();
      appendResultData(result, outsb);
    } catch (FetchException e) {
      outsb.append(ERROR_PREFIX).append(e.getMessage()).append("\r\n");
      if ((e.getMode() == FetchExceptionMode.SPLITFILE_ERROR) && (e.errorCodes != null)) {
        outsb.append(e.errorCodes.toVerboseString());
      }
      if (e.newURI != null) outsb.append(REDIRECT_PREFIX).append(e.newURI).append("\r\n");
    }
    return false;
  }

  /**
   * Handle the GETFILE command.
   *
   * <p>Handlers return whether the connection should close; GETFILE keeps the session open and
   * therefore always returns {@code false}. This is intentional.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleGetFile(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String key = line.substring("GETFILE:".length()).trim();
    LOG.info(LOG_KEY_LITERAL, key);
    FreenetURI uri;
    try {
      uri = new FreenetURI(key);
    } catch (MalformedURLException e2) {
      outsb.append(MALFORMED_URI_LITERAL).append(key).append(" : ").append(e2);
      return false;
    }
    try {
      long startTime = System.currentTimeMillis();
      FetchResult result = client.fetch(uri);
      ClientMetadata cm = result.getMetadata();
      outsb.append(CONTENT_MIME_LITERAL).append(cm.getMIMEType());
      Bucket data = result.asBucket();
      String fnam = uri.getDocName();
      fnam = sanitize(fnam);
      if (fnam.isEmpty()) {
        fnam = "freenet-download-" + HexUtil.bytesToHex(BucketTools.hash(data), 0, 10);
        String ext = DefaultMIMETypes.getExtension(cm.getMIMEType());
        if ((ext != null) && !ext.isEmpty()) fnam += '.' + ext;
      }
      File f = new File(downloadsDir, fnam);
      if (f.exists()) {
        outsb.append("File exists already: ").append(fnam);
        fnam = "freenet-" + System.currentTimeMillis() + '-' + fnam;
      }
      writeBucketToFile(data, f, outsb, fnam);
      long endTime = System.currentTimeMillis();
      long sz = data.size();
      double rate = 1000.0 * sz / (endTime - startTime);
      outsb.append("Download rate: ").append(rate).append(" bytes / second");
    } catch (FetchException e) {
      outsb.append(ERROR_PREFIX).append(e.getMessage());
      if ((e.getMode() == FetchExceptionMode.SPLITFILE_ERROR) && (e.errorCodes != null)) {
        outsb.append(e.errorCodes.toVerboseString());
      }
      if (e.newURI != null) outsb.append(REDIRECT_PREFIX).append(e.newURI).append("\r\n");
    }
    return false;
  }

  /**
   * Handle the UPDATE command.
   *
   * <p>Keeps the TMCI session open; intentionally always returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleUpdate(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    outsb.append("starting the update process");
    n.getTicker().queueTimedJob(() -> n.getNodeUpdater().arm(), 0);
    return false;
  }

  /**
   * Handle the FILTER command.
   *
   * <p>Handlers return whether the TMCI session should close after processing. FILTER keeps the
   * session open and therefore intentionally always returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleFilter(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    outsb.append("Here is the result:\r\n");
    final String content = readLines(reader, false);
    if (content == null) {
      outsb.append("Error: Unexpected end of input");
      return false;
    }
    byte[] inBytes = content.getBytes(StandardCharsets.UTF_8);
    try (InputStream inputStream = new ByteArrayInputStream(inBytes);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
      ContentFilter.filter(
          inputStream,
          outputStream,
          "text/html",
          new URI(FILTER_BASE_URL),
          null,
          null,
          null,
          null,
          core.getEndpoints().getToadletContainer());
      outsb.append(outputStream.toString(StandardCharsets.UTF_8));
    } catch (IOException e) {
      outsb.append("Bucket error?: ").append(e.getMessage());
      LOG.error("Bucket error?: {}", e, e);
    } catch (URISyntaxException e) {
      outsb.append("Internal error: ").append(e.getMessage());
      LOG.error("Internal error: {}", e, e);
    }
    return false;
  }

  /**
   * Handle the BLOW command.
   *
   * <p>Keeps the TMCI session open; intentionally always returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleBlow(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    n.getNodeUpdater().blow("caught an  IOException : (Incompetent Operator) :p", true);
    return false;
  }

  /**
   * Handle the SHUTDOWN command.
   *
   * <p>Keeps the TMCI session open from the handler perspective; underlying node begins shutdown.
   * Intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleShutdown(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    w.write("Shutting node down.\r\n");
    w.flush();
    n.exit("Shutdown from console");
    return false;
  }

  /**
   * Handle the RESTART command.
   *
   * <p>Keeps the TMCI session open; intentionally always returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleRestart(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    w.write("Restarting the node.\r\n");
    w.flush();
    n.getNodeStarter().restart();
    return false;
  }

  private boolean handleQuit(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    if (core.getEndpoints().getDirectTMCI() == this) {
      outsb.append("QUIT command not available in console mode.");
      return false;
    }
    outsb.append("Closing connection.");
    return true;
  }

  /**
   * Handle the MEMSTAT command.
   *
   * <p>Displays memory/OS info and keeps the session open; intentionally always returns {@code
   * false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleMemstat(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    Runtime rt = Runtime.getRuntime();
    float freeMemory = rt.freeMemory();
    float totalMemory = rt.totalMemory();
    float maxMemory = rt.maxMemory();
    long usedJavaMem = (long) (totalMemory - freeMemory);
    long allocatedJavaMem = (long) totalMemory;
    long maxJavaMem = (long) maxMemory;
    int availableCpus = rt.availableProcessors();
    NumberFormat thousendPoint = NumberFormat.getInstance();
    ThreadMXBean tmx = ManagementFactory.getThreadMXBean();
    int threadCount = tmx.getThreadCount();
    String sb =
        "Used Java memory:\u00a0"
            + SizeUtil.formatSize(usedJavaMem, true)
            + "\r\n"
            + "Allocated Java memory:\u00a0"
            + SizeUtil.formatSize(allocatedJavaMem, true)
            + "\r\n"
            + "Maximum Java memory:\u00a0"
            + SizeUtil.formatSize(maxJavaMem, true)
            + "\r\n"
            + "Running threads:\u00a0"
            + thousendPoint.format(threadCount)
            + "\r\n"
            + "Available CPUs:\u00a0"
            + availableCpus
            + "\r\n"
            + "Java Version:\u00a0"
            + System.getProperty("java.version")
            + "\r\n"
            + "JVM Vendor:\u00a0"
            + System.getProperty("java.vendor")
            + "\r\n"
            + "JVM Version:\u00a0"
            + System.getProperty("java.version")
            + "\r\n"
            + "OS Name:\u00a0"
            + new AppEnv().osNameRaw()
            + "\r\n"
            + "OS Version:\u00a0"
            + System.getProperty("os.version")
            + "\r\n"
            + "OS Architecture:\u00a0"
            + System.getProperty("os.arch")
            + "\r\n";
    w.write(sb);
    w.flush();
    return false;
  }

  /**
   * Handle the HELP command.
   *
   * <p>Prints the header and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleHelp(String line, String uline, BufferedReader reader, StringBuilder outsb)
      throws IOException {
    printHeader(w);
    outsb.append("\r\n");
    w.write(outsb.toString());
    w.flush();
    return false;
  }

  /**
   * Handle the PUT/GETCHK command.
   *
   * <p>Computes/does insert and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePutOrGetChk(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    boolean getCHKOnly = uline.startsWith("GETCHK:");
    if (getCHKOnly) line = line.substring(("GETCHK:").length()).trim();
    else line = line.substring("PUT:".length()).trim();
    String content;
    if (!line.isEmpty()) {
      content = line;
    } else {
      content = readLines(reader, false);
    }
    if (content == null) {
      outsb.append("Error: Unexpected end of input");
      return false;
    }
    byte[] data = content.getBytes(ENCODING);
    InsertBlock block = new InsertBlock(new ArrayBucket(data), null, FreenetURI.EMPTY_CHK_URI);
    FreenetURI uri;
    try {
      uri = client.insert(block, getCHKOnly, null);
    } catch (InsertException e) {
      outsb.append(ERROR_PREFIX).append(e.getMessage());
      if (e.getUri() != null) outsb.append(URI_WOULD_HAVE_BEEN).append(e.getUri());
      InsertExceptionMode mode = e.getMode();
      if ((mode == InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS)
          || (mode == InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS)) {
        outsb.append("Splitfile-specific error:\n").append(e.getErrorCodes().toVerboseString());
      }
      return false;
    }
    outsb.append(URI_PREFIX).append(uri);
    return false;
  }

  /**
   * Handle the PUTDIR/PUTSSKDIR/GETCHKDIR commands.
   *
   * <p>Performs manifest operations and keeps the session open; intentionally returns {@code
   * false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePutDirOrPutSSKDirOrGetCHKDir(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    DirInsertParams params;
    try {
      params = parseDirInsertParams(uline, line);
    } catch (MalformedURLException e) {
      outsb.append(MALFORMED_URI_LITERAL).append(line).append(" : ").append(e);
      return false;
    }
    String linePath = params.path.trim();
    if (linePath.isEmpty()) {
      printHeader(w);
      return false;
    }
    String defaultFile = params.defaultFile;
    FreenetURI insertURI = params.insertURI;
    // parameters already parsed by parseDirInsertParams
    HashMap<String, Object> bucketsByName = makeBucketsByName(linePath);
    if (defaultFile == null) {
      defaultFile =
          detectDefaultFile(
              bucketsByName, "index.html", "index.htm", "default.html", "default.htm");
    }
    FreenetURI uri;
    try {
      uri = client.insertManifest(insertURI, bucketsByName, defaultFile);
      uri = uri.addMetaStrings(new String[] {""});
      outsb.append("=======================================================");
      outsb.append(URI_PREFIX).append(uri);
      outsb.append("=======================================================");
    } catch (InsertException e) {
      outsb.append(FINISHED_INSERT_BUT).append(e.getMessage());
      if (e.getUri() != null) {
        uri = e.getUri();
        uri = uri.addMetaStrings(new String[] {""});
        outsb.append(URI_WOULD_HAVE_BEEN).append(uri);
      }
      if (e.getErrorCodes() != null) {
        outsb.append("Splitfile errors breakdown:");
        outsb.append(e.getErrorCodes().toVerboseString());
      }
      LOG.error(LOG_CAUGHT, e, e);
    }
    return false;
  }

  private static String detectDefaultFile(
      HashMap<String, Object> bucketsByName, String... candidates) {
    for (String file : candidates) {
      if (bucketsByName.containsKey(file)) {
        return file;
      }
    }
    return null;
  }

  private record DirInsertParams(
      boolean ssk, FreenetURI insertURI, String path, String defaultFile) {}

  private DirInsertParams parseDirInsertParams(String uline, String line)
      throws MalformedURLException {
    boolean ssk = false;
    if (uline.startsWith("PUTDIR:")) line = line.substring("PUTDIR:".length());
    else if (uline.startsWith("PUTSSKDIR:")) {
      line = line.substring("PUTSSKDIR:".length());
      ssk = true;
    } else if (uline.startsWith("GETCHKDIR:")) {
      line = line.substring(("GETCHKDIR:").length());
    } else {
      LOG.warn("Impossible");
    }
    line = line.trim();
    String defaultFile = null;
    FreenetURI insertURI = FreenetURI.EMPTY_CHK_URI;
    if (line.indexOf('#') >= 0) {
      String[] split = line.split("#");
      if (ssk) {
        insertURI = new FreenetURI(split[0]);
        line = split[1];
        if (split.length > 2) defaultFile = split[2];
      } else {
        defaultFile = split[1];
        line = split[0];
      }
    }
    return new DirInsertParams(ssk, insertURI, line, defaultFile);
  }

  /**
   * Handle the PUTFILE/GETCHKFILE commands.
   *
   * <p>Operates on local files and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "java:S1181", "SameReturnValue"})
  private boolean handlePutFileOrGetCHKFile(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    boolean getCHKOnly = uline.startsWith("GETCHKFILE:");
    if (getCHKOnly) {
      line = line.substring(("GETCHKFILE:").length()).trim();
    } else {
      line = line.substring("PUTFILE:".length()).trim();
    }
    String mimeType = DefaultMIMETypes.guessMIMEType(line, false);
    if (line.indexOf('#') > -1) {
      String[] splittedLine = line.split("#");
      line = splittedLine[0];
      mimeType = splittedLine[1];
    }
    File f = new File(line);
    outsb.append("Attempting to read file ").append(line);
    long startTime = System.currentTimeMillis();
    try (FileBucket fb = new FileBucket(f, true, false, false, false)) {
      if (!(f.exists() && f.canRead())) {
        throw new FileNotFoundException();
      }
      outsb.append(" using MIME type: ").append(mimeType).append("\r\n");
      if (DefaultMIMETypes.DEFAULT_MIME_TYPE.equals(mimeType)) mimeType = "";
      InsertBlock block =
          new InsertBlock(fb, new ClientMetadata(mimeType), FreenetURI.EMPTY_CHK_URI);
      startTime = System.currentTimeMillis();
      FreenetURI uri = client.insert(block, getCHKOnly, f.getName());
      outsb.append(URI_PREFIX).append(uri).append("\r\n");
      long endTime = System.currentTimeMillis();
      long sz = f.length();
      double rate = 1000.0 * sz / (endTime - startTime);
      outsb.append("Upload rate: ").append(rate).append(" bytes / second\r\n");
    } catch (FileNotFoundException _) {
      outsb.append("File not found");
    } catch (InsertException e) {
      outsb.append(FINISHED_INSERT_BUT).append(e.getMessage());
      if (e.getUri() != null) {
        outsb.append(URI_WOULD_HAVE_BEEN).append(e.getUri());
        long endTime = System.currentTimeMillis();
        long sz = f.length();
        double rate = 1000.0 * sz / (endTime - startTime);
        outsb.append("Upload rate: ").append(rate).append(" bytes / second");
      }
      if (e.getErrorCodes() != null) {
        outsb.append("Splitfile errors breakdown:");
        outsb.append(e.getErrorCodes().toVerboseString());
      }
    } catch (Throwable t) {
      outsb.append("Insert threw: ").append(t);
      LOG.debug("Insert threw", t);
    }
    return false;
  }

  /**
   * Handle the MAKESSK command.
   *
   * <p>Generates keys and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleMakeSSK(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    InsertableClientSSK key = InsertableClientSSK.createRandom(r, "");
    outsb.append("Insert URI: ").append(key.getInsertURI().toString(false, false)).append("\r\n");
    outsb.append("Request URI: ").append(key.getURI().toString(false, false)).append("\r\n");
    FreenetURI insertURI = key.getInsertURI().setDocName("testsite");
    String fixedInsertURI = insertURI.toString(false, false);
    outsb
        .append("Note that you MUST add a filename to the end of the above URLs e.g.:\r\n")
        .append(fixedInsertURI)
        .append("\r\n");
    outsb
        .append(
            "Normally you will then do PUTSSKDIR:<insert URI>#<directory to upload>, for"
                + " example:\r\n"
                + "PUTSSKDIR:")
        .append(fixedInsertURI)
        .append("#directoryToUpload/\r\n");
    outsb
        .append(
            "This will then produce a manifest site containing all the files, the default"
                + " document can be accessed at\r\n")
        .append(key.getURI().toString(false, false))
        .append("testsite/");
    return false;
  }

  /**
   * Handle the PUTSSK command.
   *
   * <p>Inserts a redirect and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePutSSK(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String cmd = line.substring("PUTSSK:".length());
    cmd = cmd.trim();
    if (cmd.indexOf(';') <= 0) {
      outsb.append("No target URI provided.");
      outsb.append("PUTSSK:<insert uri>;<url to redirect to>");
      return false;
    }
    String[] split = cmd.split(";");
    String insertURI = split[0];
    String targetURI = split[1];
    outsb.append("Insert URI: ").append(insertURI);
    outsb.append("Target URI: ").append(targetURI);
    FreenetURI insert = new FreenetURI(insertURI);
    FreenetURI target = new FreenetURI(targetURI);
    try {
      FreenetURI result = client.insertRedirect(insert, target);
      outsb.append("Successfully inserted to fetch URI: ").append(result);
    } catch (InsertException e) {
      outsb.append(FINISHED_INSERT_BUT).append(e.getMessage());
      LOG.info("Error: {}", e, e);
      if (e.getUri() != null) {
        outsb.append(URI_WOULD_HAVE_BEEN).append(e.getUri());
      }
    }
    return false;
  }

  /**
   * Handle the STATUS command.
   *
   * <p>Reports status and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleStatus(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    outsb.append("DARKNET:\n");
    SimpleFieldSet fs = n.exportDarknetPublicFieldSet();
    outsb.append(fs.toString());
    if (n.isOpennetEnabled()) {
      outsb.append("OPENNET:\n");
      fs = n.exportOpennetPublicFieldSet();
      outsb.append(fs.toString());
    }
    outsb.append(n.getStatus());
    if (Version.currentBuildNumber() < Version.getHighestSeenBuild()) {
      outsb.append("The latest version is : ").append(Version.getHighestSeenBuild());
    }
    return false;
  }

  /**
   * Handle the ADDPEER/CONNECT commands.
   *
   * <p>Adds a peer and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleAddPeerOrConnect(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String key;
    if (uline.startsWith("CONNECT:")) {
      key = line.substring("CONNECT:".length()).trim();
    } else {
      key = line.substring("ADDPEER:".length()).trim();
    }
    String content;
    if (!key.isEmpty()) {
      outsb.append("Trying to add peer to node by noderef in ").append(key).append("\r\n");
      File f = new File(key);
      if (f.isFile()) {
        outsb.append("Given string seems to be a file, loading...\r\n");
        try (BufferedReader fileReader =
            new BufferedReader(new InputStreamReader(new FileInputStream(f), ENCODING))) {
          content = readLines(fileReader, true);
        }
      } else {
        outsb.append("Given string seems to be an URL, loading...\r\n");
        URL url = parseUrl(key);
        content = AddPeer.getReferenceFromURL(url).toString();
      }
    } else {
      content = readLines(reader, true);
    }
    if (content == null) return false;
    if (content.isEmpty()) return false;
    addPeer(content, outsb);
    return false;
  }

  /**
   * Handle the NAME command.
   *
   * <p>Updates node name and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleName(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    outsb.append("Node name currently: ").append(n.getMyName());
    String key = line.substring("NAME:".length()).trim();
    outsb.append("New name: ").append(key);
    try {
      n.setName(key);
      if (LOG.isDebugEnabled()) LOG.debug("Setting node.name to {}", key);
    } catch (Exception e) {
      LOG.error("Error setting node's name", e);
    }
    core.storeConfig();
    return false;
  }

  /**
   * Handle the DISABLEPEER command.
   *
   * <p>Updates peer state and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleDisablePeerCmd(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String nodeIdentifier = (line.substring("DISABLEPEER:".length())).trim();
    if (!havePeer(nodeIdentifier)) {
      w.write((NO_PEER_FOR_PREFIX + nodeIdentifier + "\r\n"));
      w.flush();
      return false;
    }
    if (disablePeer(nodeIdentifier)) {
      outsb.append("disable succeeded for ").append(nodeIdentifier);
    } else {
      outsb.append("disable failed for ").append(nodeIdentifier);
    }
    outsb.append("\r\n");
    return false;
  }

  /**
   * Handle the ENABLEPEER command.
   *
   * <p>Updates peer state and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleEnablePeerCmd(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String nodeIdentifier = (line.substring("ENABLEPEER:".length())).trim();
    if (!havePeer(nodeIdentifier)) {
      w.write((NO_PEER_FOR_PREFIX + nodeIdentifier + "\r\n"));
      w.flush();
      return false;
    }
    if (enablePeer(nodeIdentifier)) {
      outsb.append("enable succeeded for ").append(nodeIdentifier);
    } else {
      outsb.append("enable failed for ").append(nodeIdentifier);
    }
    outsb.append("\r\n");
    return false;
  }

  /**
   * Handle the SETPEERLISTENONLY command.
   *
   * <p>Updates peer state and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleSetPeerListenOnly(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String nodeIdentifier = (line.substring("SETPEERLISTENONLY:".length())).trim();
    if (!havePeer(nodeIdentifier)) {
      w.write((NO_PEER_FOR_PREFIX + nodeIdentifier + "\r\n"));
      w.flush();
      return false;
    }
    PeerNode pn = n.getPeerNode(nodeIdentifier);
    if (pn == null) {
      w.write((PEER_DETAILS_FAIL_PREFIX + nodeIdentifier + CRLF2));
      w.flush();
      return false;
    }
    if (!(pn instanceof DarknetPeerNode dpn)) {
      w.write(
          (ERROR_PREFIX
              + nodeIdentifier
              + " identifies a non-darknet peer and this command is only available for darknet"
              + " peers\r\n\r\n"));
      w.flush();
      return false;
    }
    dpn.setListenOnly(true);
    outsb.append("set ListenOnly suceeded for ").append(nodeIdentifier).append("\r\n");
    return false;
  }

  /**
   * Handle the UNSETPEERLISTENONLY command.
   *
   * <p>Updates peer state and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleUnsetPeerListenOnly(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String nodeIdentifier = (line.substring("UNSETPEERLISTENONLY:".length())).trim();
    if (!havePeer(nodeIdentifier)) {
      w.write((NO_PEER_FOR_PREFIX + nodeIdentifier + "\r\n"));
      w.flush();
      return false;
    }
    PeerNode pn = n.getPeerNode(nodeIdentifier);
    if (pn == null) {
      w.write((PEER_DETAILS_FAIL_PREFIX + nodeIdentifier + CRLF2));
      w.flush();
      return false;
    }
    if (!(pn instanceof DarknetPeerNode dpn)) {
      w.write(
          (ERROR_PREFIX
              + nodeIdentifier
              + " identifies a non-darknet peer and this command is only available for darknet"
              + " peers\r\n\r\n"));
      w.flush();
      return false;
    }
    dpn.setListenOnly(false);
    outsb.append("unset ListenOnly suceeded for ").append(nodeIdentifier).append("\r\n");
    return false;
  }

  /**
   * Handle the HAVEPEER command.
   *
   * <p>Reports existence and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleHavePeerCmd(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    String nodeIdentifier = (line.substring("HAVEPEER:".length())).trim();
    if (havePeer(nodeIdentifier)) {
      outsb.append("true for ").append(nodeIdentifier);
    } else {
      outsb.append("false for ").append(nodeIdentifier);
    }
    outsb.append("\r\n");
    return false;
  }

  /**
   * Handle the REMOVEPEER/DISCONNECT commands.
   *
   * <p>Removes a peer and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleRemovePeerOrDisconnect(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    String nodeIdentifier;
    if (uline.startsWith("DISCONNECT:")) {
      nodeIdentifier = line.substring("DISCONNECT:".length());
    } else {
      nodeIdentifier = line.substring("REMOVEPEER:".length());
    }
    if (removePeer(nodeIdentifier)) {
      outsb.append("peer removed for ").append(nodeIdentifier);
    } else {
      outsb.append("peer removal failed for ").append(nodeIdentifier);
    }
    outsb.append("\r\n");
    return false;
  }

  /**
   * Handle the PEER command.
   *
   * <p>Prints peer noderef and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePeer(String line, String uline, BufferedReader reader, StringBuilder outsb)
      throws IOException {
    String nodeIdentifier = (line.substring("PEER:".length())).trim();
    if (!havePeer(nodeIdentifier)) {
      w.write((NO_PEER_FOR_PREFIX + nodeIdentifier + "\r\n"));
      w.flush();
      return false;
    }
    PeerNode pn = n.getPeerNode(nodeIdentifier);
    if (pn == null) {
      w.write((PEER_DETAILS_FAIL_PREFIX + nodeIdentifier + CRLF2));
      w.flush();
      return false;
    }
    SimpleFieldSet fs = pn.exportFieldSet();
    outsb.append(fs.toString());
    return false;
  }

  /**
   * Handle the PEERWMD command.
   *
   * <p>Prints peer noderef + metadata and keeps the session open; intentionally returns {@code
   * false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePeerWmd(
      String line, String uline, BufferedReader reader, StringBuilder outsb) throws IOException {
    String nodeIdentifier = (line.substring("PEERWMD:".length())).trim();
    if (!havePeer(nodeIdentifier)) {
      w.write((NO_PEER_FOR_PREFIX + nodeIdentifier + "\r\n"));
      w.flush();
      return false;
    }
    PeerNode pn = n.getPeerNode(nodeIdentifier);
    if (pn == null) {
      w.write((PEER_DETAILS_FAIL_PREFIX + nodeIdentifier + CRLF2));
      w.flush();
      return false;
    }
    SimpleFieldSet fs = pn.exportFieldSet();
    SimpleFieldSet meta = pn.exportMetadataFieldSet(System.currentTimeMillis());
    if (!meta.isEmpty()) fs.put("metadata", meta);
    outsb.append(fs.toString());
    return false;
  }

  /**
   * Handle the PEERS command.
   *
   * <p>Lists peers and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePeers(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    outsb.append(n.getTMCIPeerList());
    outsb.append("PEERS done.\r\n");
    return false;
  }

  /**
   * Handle the PLUGLOAD command.
   *
   * <p>Loads a plugin and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePlugLoad(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    // Support legacy bare form "PLUGLOAD" (no colon) by showing help
    if (!uline.startsWith("PLUGLOAD:")) {
      outsb.append(PLUGLOAD_HELP);
      return false;
    }

    String cmd = line.substring("PLUGLOAD:".length());
    // Help
    if (cmd.startsWith("?")) {
      outsb.append(PLUGLOAD_HELP);
      return false;
    }

    // Dispatch per legacy prefixes
    if (uline.startsWith("PLUGLOAD:O:")) {
      String name = line.substring("PLUGLOAD:O:".length()).trim();
      n.getPluginManager().startPluginOfficial(name, true);
      return false;
    }
    if (uline.startsWith("PLUGLOAD:F:")) {
      String name = line.substring("PLUGLOAD:F:".length()).trim();
      n.getPluginManager().startPluginFile(name, true);
      return false;
    }
    if (uline.startsWith("PLUGLOAD:U:")) {
      String name = line.substring("PLUGLOAD:U:".length()).trim();
      n.getPluginManager().startPluginURL(name, true);
      return false;
    }
    if (uline.startsWith("PLUGLOAD:K:")) {
      String name = line.substring("PLUGLOAD:K:".length()).trim();
      n.getPluginManager().startPluginFreenet(name, true);
      return false;
    }

    // Unknown form → show help
    outsb.append(PLUGLOAD_HELP);
    return false;
  }

  /**
   * Handle the PLUGLIST command.
   *
   * <p>Lists plugins and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePlugList(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    outsb.append(n.getPluginManager().dumpPlugins());
    return false;
  }

  /**
   * Handle the PLUGKILL command.
   *
   * <p>Kills a plugin and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handlePlugKill(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    String id = line.substring("PLUGKILL:".length()).trim();
    boolean killed = false;

    // Prefer PLUGLIST-style IDs (thread names)
    for (network.crypta.pluginmanager.PluginInfoWrapper pi : n.getPluginManager().getPlugins()) {
      if (id.equals(pi.getThreadName())) {
        pi.stopPlugin(
            n.getPluginManager(), java.util.concurrent.TimeUnit.MINUTES.toMillis(1), false);
        killed = true;
        break;
      }
    }

    // Fallback: class or filename identifiers
    if (!killed) {
      network.crypta.pluginmanager.PluginInfoWrapper info =
          n.getPluginManager().findPluginByIdentifier(id);
      if (info != null) {
        info.stopPlugin(
            n.getPluginManager(), java.util.concurrent.TimeUnit.MINUTES.toMillis(1), false);
        killed = true;
      }
    }

    outsb.append(killed ? "OK\r\n" : "FAIL\r\n");
    return false;
  }

  /**
   * Handle the ANNOUNCE command.
   *
   * <p>Runs announcement and keeps the session open; intentionally returns {@code false}.
   */
  @SuppressWarnings({"java:S3516", "SameReturnValue"})
  private boolean handleAnnounce(
      String line, String uline, BufferedReader reader, StringBuilder outsb) {
    // Guard when opennet is disabled
    var om = n.getOpennet();
    if (om == null) {
      outsb.append("OPENNET DISABLED, cannot announce.");
      return false;
    }

    double target;
    if (line.contains(":")) {
      String locStr = line.substring(line.indexOf(':') + 1).trim();
      try {
        target = Double.parseDouble(locStr);
      } catch (NumberFormatException _) {
        outsb.append("Bad location: ").append(locStr);
        return false;
      }
    } else {
      // Legacy behavior: pick a fresh random target when none is provided
      target = n.getRandom().nextDouble();
    }
    outsb.append("Announcing to ").append(target);
    om.announce(
        target,
        new AnnouncementCallback() {
          private void write(String s) {
            try {
              w.write("ANNOUNCE:" + target + ":" + s + "\r\n");
              w.flush();
            } catch (IOException _) {
              // Ignore
            }
          }

          @Override
          public void addedNode(PeerNode pn) {
            write("Added node " + pn.shortToString());
          }

          @Override
          public void bogusNoderef(String reason) {
            write("Bogus noderef: " + reason);
          }

          @Override
          public void completed() {
            write("Completed announcement.");
          }

          @Override
          public void nodeFailed(PeerNode pn, String reason) {
            write("Node failed: " + pn + " " + reason);
          }

          @Override
          public void noMoreNodes() {
            write("Route Not Found");
          }

          @Override
          public void nodeNotWanted() {
            write("Hop doesn't want me.");
          }

          @Override
          public void nodeNotAdded() {
            write("Node not added as we don't want it for some reason.");
          }

          @Override
          public void acceptedSomewhere() {
            write("Announcement accepted by some node.");
          }

          @Override
          public void relayedNoderef() {
            write(
                "Announcement returned a noderef that we relayed downstream. THIS SHOULD NOT"
                    + " HAPPEN!");
          }
        });
    return false;
  }

  private void writeBucketToFile(Bucket data, File target, StringBuilder outsb, String name) {
    try (FileOutputStream fos = new FileOutputStream(target)) {
      BucketTools.copyTo(data, fos, Long.MAX_VALUE);
      outsb.append("Written to ").append(name);
    } catch (IOException e) {
      outsb.append("Could not write file: caught ").append(e);
      LOG.debug("Could not write file", e);
    }
  }

  /** Create a map of String -> Bucket for every file in a directory and its subdirs. */
  private HashMap<String, Object> makeBucketsByName(String directory) {

    if (!directory.endsWith("/")) directory = directory + '/';
    File thisdir = new File(directory);

    LOG.info("Listing dir: {}", thisdir);

    HashMap<String, Object> ret = new HashMap<>();

    File[] filelist = thisdir.listFiles();
    if (filelist == null) throw new IllegalArgumentException("No such directory");
    for (File file : filelist) {
      //   Skip unreadable files and dirs
      //   Skip files nonexistant (dangling symlinks) - check last
      if (file.canRead() && file.exists()) {
        if (file.isFile()) {

          FileBucket bucket = new FileBucket(file, true, false, false, false);

          ret.put(file.getName(), bucket);
        } else if (file.isDirectory()) {
          HashMap<String, Object> subdir = makeBucketsByName(directory + file.getName());
          ret.put(file.getName(), subdir);
        }
      }
    }
    return ret;
  }

  /**
   * @return A block of text, input from stdin, ending with a . on a line by itself. Does some
   *     mangling for a fieldset if isFieldSet.
   */
  private String readLines(BufferedReader reader, boolean isFieldSet) {
    StringBuilder sb = new StringBuilder(1000);
    while (true) {
      String line = safeReadLine(reader);
      if (line == null) return null;
      boolean shouldBreak = false;
      boolean append = true;
      if (!isFieldSet && ".".equals(line)) {
        shouldBreak = true;
        append = false;
      }
      if (isFieldSet) {
        LineResult result = processFieldSetLine(line);
        line = result.line;
        if (result.shouldBreak) {
          shouldBreak = true;
        }
      }
      if (append) sb.append(line).append("\r\n");
      if (shouldBreak) break;
    }
    return sb.toString();
  }

  private String safeReadLine(BufferedReader reader) {
    try {
      String line = reader.readLine();
      if (line == null) throw new EOFException();
      return line;
    } catch (IOException e1) {
      LOG.warn("Bye... ({} )", e1, e1);
      return null;
    }
  }

  private record LineResult(String line, boolean shouldBreak) {}

  private LineResult processFieldSetLine(String input) {
    String line = input.trim();
    if (line.equals("End")) {
      return new LineResult("End", true);
    }
    if (line.endsWith("End")
        && line.length() > "End".length()
        && Character.isWhitespace(line.charAt(line.length() - ("End".length() + 1)))) {
      return new LineResult("End", true);
    }
    int idx = line.indexOf('=');
    if (idx < 0) {
      LOG.warn("No = and no End in line: {}", line);
      return new LineResult("", false);
    }
    if (idx == 0) {
      LOG.warn("Invalid empty field name");
      return new LineResult(line, true);
    }
    String after = (idx == line.length() - 1) ? "" : line.substring(idx + 1);
    String before = line.substring(0, idx).trim();
    int x = 0;
    for (int j = before.length() - 1; j >= 0; j--) {
      char c = before.charAt(j);
      if ((c != '.') && !Character.isLetterOrDigit(c)) {
        x = j + 1;
        break;
      }
    }
    before = before.substring(x);
    return new LineResult(before + '=' + after, false);
  }

  /** Add a peer to the node, given its reference, and emit user-visible feedback. */
  private void addPeer(String content, StringBuilder outsb) {
    SimpleFieldSet fs;
    LOG.info("Connecting to:\r\n{}", content);
    try {
      fs = new SimpleFieldSet(content, false, true, false);
    } catch (IOException e) {
      LOG.error(DID_NOT_PARSE_LITERAL, e, e);
      outsb.append("Did not parse: ").append(e).append("\r\n");
      return;
    }
    PeerNode pn;
    try {
      pn = n.createNewDarknetNode(fs, FRIEND_TRUST.NORMAL, FRIEND_VISIBILITY.NO);
    } catch (FSParseException
        | PeerTooOldException
        | ReferenceSignatureVerificationException
        | PeerParseException e1) {
      LOG.error(DID_NOT_PARSE_LITERAL, e1, e1);
      outsb.append("Did not parse: ").append(e1).append("\r\n");
      return;
    }
    if (n.getPeers().addPeer(pn)) {
      LOG.info("Added peer: {}", pn);
      outsb.append("Added peer: ").append(pn).append("\r\n");
    }
    n.getPeers().writePeersDarknetUrgent();
  }

  /**
   * Disable connecting to a peer given its ip and port, name or identity, as a String Report peer
   * success as boolean
   */
  private boolean disablePeer(String nodeIdentifier) {
    for (DarknetPeerNode pn : n.getPeers().roster().getDarknetPeers()) {
      Peer peer = pn.getPeer();
      String nodeIpAndPort = "";
      if (peer != null) {
        nodeIpAndPort = peer.toString();
      }
      String name = pn.myName;
      String identity = pn.getIdentityString();
      if (identity.equals(nodeIdentifier)
          || nodeIpAndPort.equals(nodeIdentifier)
          || name.equals(nodeIdentifier)) {
        pn.disablePeer();
        return true;
      }
    }
    return false;
  }

  /**
   * Enable connecting to a peer given its ip and port, name or identity, as a String Report peer
   * success as boolean
   */
  private boolean enablePeer(String nodeIdentifier) {
    for (DarknetPeerNode pn : n.getPeers().roster().getDarknetPeers()) {
      Peer peer = pn.getPeer();
      String nodeIpAndPort = "";
      if (peer != null) {
        nodeIpAndPort = peer.toString();
      }
      String name = pn.myName;
      String identity = pn.getIdentityString();
      if (identity.equals(nodeIdentifier)
          || nodeIpAndPort.equals(nodeIdentifier)
          || name.equals(nodeIdentifier)) {
        pn.enablePeer();
        return true;
      }
    }
    return false;
  }

  /**
   * Check for a peer of the node given its ip and port, name or identity, as a String Report peer
   * existence as boolean
   */
  private boolean havePeer(String nodeIdentifier) {
    for (DarknetPeerNode pn : n.getPeers().roster().getDarknetPeers()) {
      Peer peer = pn.getPeer();
      String nodeIpAndPort = "";
      if (peer != null) {
        nodeIpAndPort = peer.toString();
      }
      String name = pn.myName;
      String identity = pn.getIdentityString();
      if (identity.equals(nodeIdentifier)
          || nodeIpAndPort.equals(nodeIdentifier)
          || name.equals(nodeIdentifier)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Remove a peer from the node given its ip and port, name or identity, as a String Report peer
   * removal successfulness as boolean
   */
  private boolean removePeer(String nodeIdentifier) {
    LOG.info("Removing peer from node for: {}", nodeIdentifier);
    for (DarknetPeerNode pn : n.getPeers().roster().getDarknetPeers()) {
      Peer peer = pn.getPeer();
      String nodeIpAndPort = "";
      if (peer != null) {
        nodeIpAndPort = peer.toString();
      }
      String name = pn.myName;
      String identity = pn.getIdentityString();
      if (identity.equals(nodeIdentifier)
          || nodeIpAndPort.equals(nodeIdentifier)
          || name.equals(nodeIdentifier)) {
        n.removePeerConnection(pn);
        return true;
      }
    }
    LOG.info("No node in peers list for: {}", nodeIdentifier);
    return false;
  }

  private String sanitize(String fnam) {
    if (fnam == null) return "";
    StringBuilder sb = new StringBuilder(fnam.length());
    for (int i = 0; i < fnam.length(); i++) {
      char c = fnam.charAt(i);
      if (Character.isLetterOrDigit(c) || (c == '-') || (c == '.')) sb.append(c);
    }
    return sb.toString();
  }
}
