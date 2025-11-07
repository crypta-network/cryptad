/* -*- Mode: java; c-basic-indent: 4; tab-width: 4 -*- */

package network.crypta.client.filter;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.Charset;
import java.nio.charset.MalformedInputException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Stack;
import java.util.StringTokenizer;
import network.crypta.clients.http.ToadletContextImpl;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLDecoder;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.io.NullWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HTMLFilter implements ContentDataFilter, CharsetExtractor {
  private static final Logger LOG = LoggerFactory.getLogger(HTMLFilter.class);

  private static final String M3U_PLAYER_TAG_FILE =
      "network/crypta/clients/http/staticfiles/js/m3u-player.js";

  /** if true, embed m3u player. Enabled when fproxy javascript is enabled. * */
  public static boolean embedM3uPlayer = true;

  private static final boolean DELETE_WIERD_STUFF = true;
  private static final boolean DELETE_ERRORS = true;

  /**
   * If true, allow documents that don't have an <html> tag or have other tags before it. In all
   * cases we disallow text before the first valid tag. This is because if we don't, charset
   * detection can be ambiguous, potentially resulting in attacks.
   */
  private static final boolean ALLOW_NO_HTML_TAG = true;

  // FIXME make these configurable on a per-document level.
  // Maybe by merging with TagReplacerCallback???
  // For now they're just global.
  /** -1 means don't allow it */
  public static int metaRefreshSamePageMinInterval = 1;

  /** -1 means don't allow it */
  public static int metaRefreshRedirectMinInterval = 30;

  private static final String M3U_PLAYER_SCRIPT_TAG_CONTENT = loadM3uPlayerScriptTagContent();

  private static final class HtmlStrings {
    private HtmlStrings() {}

    static final String STR_COMMENT_PREFIX = "<!-- ";
    static final String STR_DELETING_XML_DECLARATION_INVALID_ENCODING =
        "Deleting xml declaration, invalid encoding";
    static final String STR_ACCENT = "accent";
    static final String STR_ACCENTUNDER = "accentunder";
    static final String STR_ACCESSKEY = "accesskey";
    static final String STR_ACTION = "action";
    static final String STR_ALIGN = "align";
    static final String STR_ALIGNMENTSCOPE = "alignmentscope";
    static final String STR_AUDIO = "audio";
    static final String STR_BACKGROUND = "background";
    static final String STR_BEVELLED = "bevelled";
    static final String STR_BGCOLOR = "bgcolor";
    static final String STR_BLOCKQUOTE = "blockquote";
    static final String STR_BUTTON = "button";
    static final String STR_CHARALIGN = "charalign";
    static final String STR_CHAROFF = "charoff";
    static final String STR_CHARSET = "charset";
    static final String STR_CHARSPACING = "charspacing";
    static final String STR_CLASS = "class";
    static final String STR_CLOSE = "close";
    static final String STR_COLUMNALIGN = "columnalign";
    static final String STR_COLUMNLINES = "columnlines";
    static final String STR_COLUMNSPACING = "columnspacing";
    static final String STR_COLUMNSPAN = "columnspan";
    static final String STR_COLUMNWIDTH = "columnwidth";
    static final String STR_COMPACT = "compact";
    static final String STR_CONTENT = "content";
    static final String STR_CROSSOUT = "crossout";
    static final String STR_DENOMALIGN = "denomalign";
    static final String STR_DEPTH = "depth";
    static final String STR_DISABLED = "disabled";
    static final String STR_DISPLAYSTYLE = "displaystyle";
    static final String STR_EQUALCOLUMNS = "equalcolumns";
    static final String STR_EQUALROWS = "equalrows";
    static final String STR_FENCE = "fence";
    static final String STR_FRAME = "frame";
    static final String STR_FRAMESPACING = "framespacing";
    static final String STR_GROUPALIGN = "groupalign";
    static final String STR_HEIGHT = "height";
    static final String STR_HREFLANG = "hreflang";
    static final String STR_HTTP_EQUIV = "http-equiv";
    static final String STR_INDENTALIGN = "indentalign";
    static final String STR_INDENTALIGNFIRST = "indentalignfirst";
    static final String STR_INDENTALIGNLAST = "indentalignlast";
    static final String STR_INDENTSHIFT = "indentshift";
    static final String STR_INDENTSHIFTFIRST = "indentshiftfirst";
    static final String STR_INDENTSHIFTLAST = "indentshiftlast";
    static final String STR_INDENTTARGET = "indenttarget";
    static final String STR_INPUT = "input";
    static final String STR_LABEL = "label";
    static final String STR_LARGEOP = "largeop";
    static final String STR_LEFTOVERHANG = "leftoverhang";
    static final String STR_LENGTH = "length";
    static final String STR_LINEBREAK = "linebreak";
    static final String STR_LINEBREAKMULTCHAR = "linebreakmultchar";
    static final String STR_LINEBREAKSTYLE = "linebreakstyle";
    static final String STR_LINELEADING = "lineleading";
    static final String STR_LINETHICKNESS = "linethickness";
    static final String STR_LOCATION = "location";
    static final String STR_LONGDESC = "longdesc";
    static final String STR_LONGDIVSTYLE = "longdivstyle";
    static final String STR_LQUOTE = "lquote";
    static final String STR_LSPACE = "lspace";
    static final String STR_MATHBACKGROUND = "mathbackground";
    static final String STR_MATHCOLOR = "mathcolor";
    static final String STR_MATHSIZE = "mathsize";
    static final String STR_MATHVARIANT = "mathvariant";
    static final String STR_MAXSIZE = "maxsize";
    static final String STR_MEDIA = "media";
    static final String STR_METER = "meter";
    static final String STR_METHOD = "method";
    static final String STR_MINLABELSPACING = "minlabelspacing";
    static final String STR_MINSIZE = "minsize";
    static final String STR_MOVABLELIMITS = "movablelimits";
    static final String STR_MSLINETHICKNESS = "mslinethickness";
    static final String STR_MULTIPLE_CHARSETS_IN_META = "multipleCharsetsInMeta";
    static final String STR_NOTATION = "notation";
    static final String STR_NUMALIGN = "numalign";
    static final String STR_ONBLUR = "onblur";
    static final String STR_ONCHANGE = "onchange";
    static final String STR_ONFOCUS = "onfocus";
    static final String STR_ONLOAD = "onload";
    static final String STR_ONSELECT = "onselect";
    static final String STR_ONUNLOAD = "onunload";
    static final String STR_OPTION = "option";
    static final String STR_POSITION = "position";
    static final String STR_REFRESH = "refresh";
    static final String STR_RIGHTOVERHANG = "rightoverhang";
    static final String STR_ROWALIGN = "rowalign";
    static final String STR_ROWLINES = "rowlines";
    static final String STR_ROWSPACING = "rowspacing";
    static final String STR_ROWSPAN = "rowspan";
    static final String STR_RQUOTE = "rquote";
    static final String STR_RSPACE = "rspace";
    static final String STR_SCRIPTSIZEMULTIPLIER = "scriptsizemultiplier";
    static final String STR_SECTION = "section";
    static final String STR_SELECT = "select";
    static final String STR_SEPARATOR = "separator";
    static final String STR_SEPARATORS = "separators";
    static final String STR_SHIFT = "shift";
    static final String STR_STACKALIGN = "stackalign";
    static final String STR_STRETCHY = "stretchy";
    static final String STR_STYLE = "style";
    static final String STR_SUBSCRIPTSHIFT = "subscriptshift";
    static final String STR_SUPERSCRIPTSHIFT = "superscriptshift";
    static final String STR_SYMMETRIC = "symmetric";
    static final String STR_TABINDEX = "tabindex";
    static final String STR_TABLE = "table";
    static final String STR_TARGET = "target";
    static final String STR_TEXT_CSS = "text/css";
    static final String STR_TEXT_BEFORE_HTML = "textBeforeHTML";
    static final String STR_TITLE = "title";
    static final String STR_VALIGN = "valign";
    static final String STR_VALUE = "value";
    static final String STR_VIDEO = "video";
    static final String STR_VOFFSET = "voffset";
    static final String STR_WIDTH = "width";
    static final String STR_XML_SPACE = "xml:space";
    static final String STR_XMLNS = "xmlns";
  }

  @Override
  public void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException {
    if (cb == null) cb = new NullFilterCallback();

    if (LOG.isDebugEnabled()) LOG.debug("readFilter(): charset=" + charset);
    Reader r = null;
    Writer w = null;
    InputStreamReader isr = null;
    OutputStreamWriter osw = null;
    try {
      isr = new InputStreamReader(input, charset);
      osw = new OutputStreamWriter(output, charset);
      r = new BufferedReader(isr, 4096);
      w = new BufferedWriter(osw, 4096);
    } catch (UnsupportedEncodingException e) {
      throw UnknownCharsetException.create(charset);
    }
    HTMLParseContext pc = new HTMLParseContext(r, w, charset, cb, false);
    pc.run();
    w.flush();
  }

  @Override
  public String getCharset(byte[] input, int length, String parseCharset) throws IOException {

    if (LOG.isDebugEnabled()) LOG.debug("getCharset(): default={}", parseCharset);
    if (length > getCharsetBufferSize() && LOG.isDebugEnabled()) {
      LOG.debug(
          "More data than was strictly needed was passed to the charset extractor for extraction");
    }
    try (ByteArrayInputStream strm = new ByteArrayInputStream(input, 0, length);
        Writer w = new NullWriter();
        Reader r = new BufferedReader(new InputStreamReader(strm, parseCharset), 4096)) {
      HTMLParseContext pc = new HTMLParseContext(r, w, null, new NullFilterCallback(), true);
      try {
        pc.run();
      } catch (MalformedInputException e) {
        return null;
      } catch (IOException e) {
        throw e;
      } catch (Exception e) {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Caught {} trying to detect MIME type with {}", e, parseCharset);
        }
      }
      if (LOG.isDebugEnabled()) LOG.debug("Returning charset {}", pc.detectedCharset);
      return pc.detectedCharset;
    }
  }

  class HTMLParseContext {
    Reader r;
    Writer w;
    String charset;
    String detectedCharset;
    final FilterCallback cb;
    final boolean onlyDetectingCharset;
    boolean isXHTML = false;
    Stack<String> openElements;
    boolean failedDetectCharset;
    final StringBuilder textBuffer = new StringBuilder(100);
    final StringBuilder tagBuffer = new StringBuilder(4000);
    final List<String> splitTag = new ArrayList<>();
    String currentTag;
    char previousChar;
    char prePreviousChar;
    char currentChar;
    boolean textAllowed;
    boolean firstChar = true;

    /**
     * If <head> is found, then it is true. It is needed that if <title> or <meta> is found outside
     * <head> or if a <body> is found first, then insert a <head> too
     */
    boolean wasHeadElementFound = false;

    /**
     * We can only have <head> once, and <meta>/<title> can't be outside it. This helps with
     * robustness against charset attacks and allows us to stop looking for <meta> as soon as we see
     * </head> when detecting charset.
     */
    boolean headEnded = false;

    /**
     * if a &lt;video&gt; or &lt;audio&gt; tag is present in the file, it makes sense to include the
     * media player.
     */
    boolean wasMediaElementFound = false;

    HTMLParseContext(
        Reader r, Writer w, String charset, FilterCallback cb, boolean onlyDetectingCharset) {
      this.r = r;
      this.w = w;
      this.charset = charset;
      this.cb = cb;
      this.onlyDetectingCharset = onlyDetectingCharset;
      openElements = new Stack<>();
    }

    public void setisXHTML(boolean value) {
      isXHTML = value;
    }

    public boolean getisXHTML() {
      return isXHTML;
    }

    public void pushElementInStack(String element) {
      openElements.push(element);
    }

    public String popElementFromStack() {
      if (!openElements.isEmpty()) return openElements.pop();
      else return null;
    }

    public String peekTopElement() {
      if (openElements.isEmpty()) return null;
      return openElements.peek();
    }

    void run() throws IOException {
      resetTokenizerState();
      mode = INTEXT;
      while (true) {
        if (shouldStopDetectingCharset()) {
          return;
        }
        int readValue = r.read();
        if (readValue == -1) {
          handleEndOfStream();
          break;
        }
        updateCharacterState((char) readValue);
        if (skipBomOrNullCharacters()) {
          continue;
        }
        dispatchTokenizerMode();
      }
      flushOpenElements();
      w.flush();
    }

    private void resetTokenizerState() {
      textBuffer.setLength(0);
      tagBuffer.setLength(0);
      splitTag.clear();
      currentTag = null;
      previousChar = 0;
      prePreviousChar = 0;
      currentChar = 0;
      textAllowed = false;
      firstChar = true;
    }

    private boolean shouldStopDetectingCharset() {
      if (!onlyDetectingCharset) {
        return false;
      }
      return failedDetectCharset || detectedCharset != null;
    }

    private void handleEndOfStream() throws IOException {
      switch (mode) {
        case INTEXT:
          flushPendingText();
          break;
        case INTAG:
          w.write("<!-- truncated page: last tag not unfinished -->");
          break;
        case INTAGQUOTES:
          w.write("<!-- truncated page: deleted unfinished tag: still in quotes -->");
          break;
        case INTAGSQUOTES:
          w.write("<!-- truncated page: deleted unfinished tag: still in single quotes -->");
          break;
        case INTAGWHITESPACE:
          w.write("<!-- truncated page: deleted unfinished tag: still in whitespace -->");
          break;
        case INTAGCOMMENT:
          w.write("<!-- truncated page: deleted unfinished comment -->");
          break;
        case INTAGCOMMENTCLOSING:
          w.write("<!-- truncated page: deleted unfinished comment, might be closing -->");
          break;
        default:
          break;
      }
    }

    private void updateCharacterState(char nextChar) {
      prePreviousChar = previousChar;
      previousChar = currentChar;
      currentChar = nextChar;
    }

    private boolean skipBomOrNullCharacters() throws IOException {
      if (currentChar == 0xFEFF) {
        if (firstChar && w != null) {
          w.write(currentChar);
        }
        firstChar = false;
        return true;
      }
      if (currentChar == 0) {
        firstChar = false;
        return true;
      }
      firstChar = false;
      return false;
    }

    private void dispatchTokenizerMode() throws IOException {
      switch (mode) {
        case INTEXT:
          handleTextMode();
          break;
        case INTAG:
          handleTagMode();
          break;
        case INTAGQUOTES:
          handleDoubleQuoteMode();
          break;
        case INTAGSQUOTES:
          handleSingleQuoteMode();
          break;
        case INTAGCOMMENT:
          handleCommentMode();
          break;
        case INTAGCOMMENTCLOSING:
          handleCommentClosingMode();
          break;
        case INTAGWHITESPACE:
          handleWhitespaceMode();
          break;
        default:
          break;
      }
    }

    private void handleTextMode() throws IOException {
      if (currentChar == '<') {
        flushPendingText();
        textBuffer.setLength(0);
        tagBuffer.setLength(0);
        mode = INTAG;
        return;
      }
      textBuffer.append(currentChar);
    }

    private void flushPendingText() throws IOException {
      if (textAllowed) {
        saveText(textBuffer, currentTag, w, this);
        return;
      }
      if (!textBuffer.toString().trim().isEmpty()) {
        throwFilterException(l10n(HtmlStrings.STR_TEXT_BEFORE_HTML));
      }
    }

    private void handleTagMode() throws IOException {
      tagBuffer.append(currentChar);
      if (HTMLDecoder.isWhitespace(currentChar)) {
        splitTag.add(textBuffer.toString());
        mode = INTAGWHITESPACE;
        textBuffer.setLength(0);
        return;
      }
      if (isUnescapedScriptStart()) {
        flushPendingText();
        tagBuffer.setLength(0);
        textBuffer.setLength(0);
        splitTag.clear();
        return;
      }
      if (currentChar == '>') {
        appendAndProcessTag();
        return;
      }
      if (startsComment()) {
        mode = INTAGCOMMENT;
        textBuffer.append(currentChar);
        return;
      }
      if (currentChar == '"') {
        mode = INTAGQUOTES;
        textBuffer.append(currentChar);
        return;
      }
      if (currentChar == '\'') {
        mode = INTAGSQUOTES;
        textBuffer.append(currentChar);
        return;
      }
      if (currentChar == '/') {
        currentTag = null;
      }
      textBuffer.append(currentChar);
    }

    private boolean isUnescapedScriptStart() {
      return currentChar == '<' && Character.isWhitespace(tagBuffer.charAt(0));
    }

    private void appendAndProcessTag() throws IOException {
      splitTag.add(textBuffer.toString());
      textBuffer.setLength(0);
      String processed = processTag(splitTag, w, this);
      currentTag = processed;
      splitTag.clear();
      tagBuffer.setLength(0);
      mode = INTEXT;
      if (processed != null
          && (ALLOW_NO_HTML_TAG
              || processed.equals("html")
              || (!isXHTML && processed.equalsIgnoreCase("html")))) {
        textAllowed = true;
      }
    }

    private boolean startsComment() {
      return (textBuffer.length() == 2)
          && (currentChar == '-')
          && (previousChar == '-')
          && (prePreviousChar == '!');
    }

    private void handleDoubleQuoteMode() {
      if (currentChar == '"') {
        mode = INTAG;
        textBuffer.append(currentChar);
        return;
      }
      if (currentChar == '>') {
        textBuffer.append("&gt;");
        return;
      }
      if (currentChar == '<') {
        textBuffer.append("&lt;");
        return;
      }
      if (currentChar == '\u00A0') {
        textBuffer.append("&nbsp;");
        return;
      }
      textBuffer.append(currentChar);
    }

    private void handleSingleQuoteMode() {
      if (currentChar == '\'') {
        mode = INTAG;
        textBuffer.append(currentChar);
        return;
      }
      if (currentChar == '<') {
        textBuffer.append("&lt;");
        return;
      }
      if (currentChar == '>') {
        textBuffer.append("&gt;");
        return;
      }
      if (currentChar == '\u00A0') {
        textBuffer.append("&nbsp;");
        return;
      }
      textBuffer.append(currentChar);
    }

    private void handleCommentMode() throws IOException {
      if (isCommentClosingStart()) {
        mode = INTAGCOMMENTCLOSING;
        textBuffer.append(currentChar);
        return;
      }
      if (isCommentEnd()) {
        writeCommentAndReset();
        return;
      }
      if (isCdataCloser()) {
        mode = INTEXT;
        return;
      }
      textBuffer.append(currentChar);
    }

    private boolean isCommentClosingStart() {
      return (currentChar == '<') && (previousChar == '-') && (prePreviousChar == '-');
    }

    private boolean isCommentEnd() {
      return (currentChar == '>') && (previousChar == '-') && (prePreviousChar == '-');
    }

    private boolean isCdataCloser() {
      return (currentChar == '>') && (previousChar == '-') && (prePreviousChar == ']');
    }

    private void handleCommentClosingMode() throws IOException {
      if (isCommentEnd()) {
        writeCommentAndReset();
        return;
      }
      if (!Character.isWhitespace(currentChar)) {
        mode = INTAGCOMMENT;
        textBuffer.append(currentChar);
        return;
      }
      mode = INTAGCOMMENTCLOSING;
    }

    private void writeCommentAndReset() throws IOException {
      saveComment(textBuffer, w, this);
      tagBuffer.setLength(0);
      textBuffer.setLength(0);
      mode = INTEXT;
    }

    private void handleWhitespaceMode() throws IOException {
      if (HTMLDecoder.isWhitespace(currentChar)) {
        return;
      }
      if (currentChar == '"') {
        mode = INTAGQUOTES;
        textBuffer.append(currentChar);
        return;
      }
      if (currentChar == '\'') {
        mode = INTAGSQUOTES;
        textBuffer.append(currentChar);
        return;
      }
      if (isUnescapedScriptStart()) {
        textBuffer.setLength(0);
        mode = INTAG;
        return;
      }
      if (currentChar == '>') {
        appendAndProcessTag();
        return;
      }
      mode = INTAG;
      textBuffer.append(currentChar);
    }

    private void flushOpenElements() throws IOException {
      if (getisXHTML()) {
        while (!openElements.isEmpty()) {
          w.write("</" + openElements.pop() + ">");
        }
      }
    }

    int mode;
    static final int INTEXT = 0;
    static final int INTAG = 1;
    static final int INTAGQUOTES = 2;
    static final int INTAGSQUOTES = 3;
    static final int INTAGCOMMENT = 4;
    static final int INTAGCOMMENTCLOSING = 5;
    static final int INTAGWHITESPACE = 6;
    boolean killTag = false; // just this one
    boolean writeStyleScriptWithTag = false; // just this one
    boolean expectingBadComment = false;
    // has to be set on or off explicitly by tags
    boolean inStyle = false; // has to be set on or off explicitly by tags
    boolean inScript = false; // has to be set on or off explicitly by tags
    boolean killText = false; // has to be set on or off explicitly by tags
    boolean killStyle = false;
    int styleScriptRecurseCount = 0;
    String currentStyleScriptChunk = "";
    StringBuilder writeAfterTag = new StringBuilder(1024);

    public void closeXHTMLTag(String element, Writer w) throws IOException {
      // Assume that missing closes are way more common than extra closes.
      if (openElements.isEmpty()) return;
      if (element.equals(openElements.peek())) {
        w.write("</" + openElements.pop() + ">");
      } else {
        if (openElements.contains(element)) {
          while (true) {
            String top = openElements.pop();
            w.write("</" + top + ">");
            if (top.equals(element)) return;
          }
        } // Else it has already been closed.
      }
    }
  }

  void saveText(StringBuilder s, String tagName, Writer w, HTMLParseContext pc) throws IOException {

    if (pc.onlyDetectingCharset || pc.killText) {
      return;
    }

    if (LOG.isTraceEnabled()) LOG.trace("Saving text: {}", s);
    String filteredText = filterVisibleText(s, pc);

    if (pc.inStyle || pc.inScript) {
      pc.currentStyleScriptChunk += filteredText;
      return; // is parsed and written elsewhere
    }
    if (pc.cb != null) {
      pc.cb.onText(HTMLDecoder.decode(filteredText), tagName);
    }

    w.write(filteredText);
  }

  private String filterVisibleText(StringBuilder text, HTMLParseContext pc) {
    StringBuilder out = new StringBuilder(text.length() * 2);
    for (int i = 0; i < text.length(); i++) {
      char current = text.charAt(i);
      appendFilteredCharacter(pc, out, current);
    }
    return out.toString();
  }

  private void appendFilteredCharacter(HTMLParseContext pc, StringBuilder out, char current) {
    if (current == '<' && !(pc.inStyle || pc.inScript)) {
      out.append("&lt;");
      return;
    }
    if ((current < 32) && (current != '\t') && (current != '\n') && (current != '\r')) {
      if (LOG.isTraceEnabled()) LOG.trace("Removing '{}' from the output stream", current);
      return;
    }
    out.append(current);
  }

  static String loadM3uPlayerScriptTagContent() {
    InputStream m3uPlayerTagStream =
        HTMLFilter.class.getClassLoader().getResourceAsStream(M3U_PLAYER_TAG_FILE);
    String errorTag = "/* Error: could not load " + M3U_PLAYER_TAG_FILE + " */";
    if (m3uPlayerTagStream == null) {
      return errorTag;
    }
    String tagContent;
    try (BufferedReader bufferedReader =
        new BufferedReader(new InputStreamReader(m3uPlayerTagStream))) {
      StringBuilder stringBuilder = new StringBuilder("<script>");
      String line;
      while ((line = bufferedReader.readLine()) != null) {
        stringBuilder.append(line);
        stringBuilder.append("\n");
      }
      stringBuilder.append("</script>");
      tagContent = stringBuilder.toString();
    } catch (IOException e) {
      LOG.error("Could not read m3uPlayer inline-script.");
      return errorTag;
    }
    return tagContent;
  }

  @Deprecated
  static String m3uPlayerScriptTagContent() {
    return loadM3uPlayerScriptTagContent();
  }

  String processTag(List<String> splitTag, Writer w, HTMLParseContext pc) throws IOException {
    if (LOG.isTraceEnabled()) {
      for (int i = 0; i < splitTag.size(); i++) {
        LOG.trace("Tag[{}]={}", i, splitTag.get(i));
      }
    }
    ParsedTag tag = new ParsedTag(splitTag);
    if (pc.killTag) {
      pc.killTag = false;
      pc.writeStyleScriptWithTag = false;
      return null;
    }

    tag = tag.sanitize(pc);
    if (tag != null) {
      updateDocumentStructure(tag, w, pc);
      if (!pc.onlyDetectingCharset) {
        writeSanitizedTag(tag, w, pc);
      } else {
        pc.writeStyleScriptWithTag = false;
      }
    }
    return determineNextCurrentTag(tag, w, pc);
  }

  private void updateDocumentStructure(ParsedTag tag, Writer w, HTMLParseContext pc)
      throws IOException {
    if (isHeadStart(tag)) {
      pc.wasHeadElementFound = true;
      return;
    }
    if (isMediaTag(tag)) {
      pc.wasMediaElementFound = true;
      return;
    }
    if (isHeadEnd(tag)) {
      pc.headEnded = true;
      if (pc.onlyDetectingCharset) {
        pc.failedDetectCharset = true;
      }
      return;
    }
    if (isMetaOrTitleBeforeHead(tag, pc)) {
      insertSyntheticHead(w, pc);
      return;
    }
    if (isMetaOrTitleAfterHead(tag, pc)) {
      throwFilterException(l10n("metaOutsideHead"));
      return;
    }
    if (bodyStartsWithoutClosingHead(tag, pc)) {
      closeOpenHead(w, pc);
      return;
    }
    if (bodyStartsBeforeHead(tag, pc)) {
      addMissingHeadBeforeBody(w, pc);
      return;
    }
    if (shouldInjectMediaPlayer(tag, pc)) {
      w.write(M3U_PLAYER_SCRIPT_TAG_CONTENT);
    }
  }

  private boolean isHeadStart(ParsedTag tag) {
    return "head".equals(tag.element) && !tag.startSlash;
  }

  private boolean isMediaTag(ParsedTag tag) {
    return !tag.startSlash
        && (HtmlStrings.STR_VIDEO.equals(tag.element) || HtmlStrings.STR_AUDIO.equals(tag.element));
  }

  private boolean isHeadEnd(ParsedTag tag) {
    return tag.startSlash && "head".equals(tag.element);
  }

  private boolean isMetaOrTitleBeforeHead(ParsedTag tag, HTMLParseContext pc) {
    return !pc.wasHeadElementFound && isMetaOrTitle(tag);
  }

  private boolean isMetaOrTitleAfterHead(ParsedTag tag, HTMLParseContext pc) {
    return pc.headEnded && isMetaOrTitle(tag);
  }

  private boolean isMetaOrTitle(ParsedTag tag) {
    return "meta".equals(tag.element) || HtmlStrings.STR_TITLE.equals(tag.element);
  }

  private void insertSyntheticHead(Writer w, HTMLParseContext pc) throws IOException {
    pc.openElements.push("head");
    pc.wasHeadElementFound = true;
    String headContent = pc.cb.processTag(new ParsedTag("head", new HashMap<>()));
    if (headContent != null && !pc.onlyDetectingCharset) {
      w.write(headContent);
    }
  }

  private boolean bodyStartsWithoutClosingHead(ParsedTag tag, HTMLParseContext pc) {
    return "body".equals(tag.element) && pc.openElements.contains("head");
  }

  private void closeOpenHead(Writer w, HTMLParseContext pc) throws IOException {
    if (!pc.onlyDetectingCharset) {
      w.write("</head>");
    }
    pc.headEnded = true;
    if (pc.onlyDetectingCharset) {
      pc.failedDetectCharset = true;
    }
    pc.openElements.pop();
  }

  private boolean bodyStartsBeforeHead(ParsedTag tag, HTMLParseContext pc) {
    return "body".equals(tag.element) && !pc.wasHeadElementFound;
  }

  private void addMissingHeadBeforeBody(Writer w, HTMLParseContext pc) throws IOException {
    pc.wasHeadElementFound = true;
    String headContent = pc.cb.processTag(new ParsedTag("head", new HashMap<>()));
    if (headContent != null && !pc.onlyDetectingCharset) {
      w.write(headContent + "</head>");
    }
    pc.headEnded = true;
    if (pc.onlyDetectingCharset) {
      pc.failedDetectCharset = true;
    }
  }

  private boolean shouldInjectMediaPlayer(ParsedTag tag, HTMLParseContext pc) {
    return tag.startSlash
        && "body".equals(tag.element)
        && pc.wasMediaElementFound
        && embedM3uPlayer;
  }

  private void writeSanitizedTag(ParsedTag tag, Writer w, HTMLParseContext pc) throws IOException {
    String newContent = pc.cb.processTag(tag);
    if (newContent != null) {
      w.write(newContent);
      if (!tag.endSlash) {
        pc.openElements.push(tag.element);
      }
      return;
    }

    writePendingStyleChunk(w, pc);
    tag.write(w, pc);
    flushWriteAfterTag(w, pc);
  }

  private void writePendingStyleChunk(Writer w, HTMLParseContext pc) throws IOException {
    if (!pc.writeStyleScriptWithTag) {
      return;
    }
    pc.writeStyleScriptWithTag = false;
    String style = pc.currentStyleScriptChunk;
    if (style == null || style.isEmpty()) {
      pc.writeAfterTag
          .append(HtmlStrings.STR_COMMENT_PREFIX)
          .append(l10n("deletedUnknownStyle"))
          .append(" -->");
    } else {
      w.write(style);
    }
    pc.currentStyleScriptChunk = "";
  }

  private String determineNextCurrentTag(ParsedTag tag, Writer w, HTMLParseContext pc)
      throws IOException {
    if (tag == null || tag.startSlash || tag.endSlash) {
      flushWriteAfterTag(w, pc);
      if (!pc.openElements.isEmpty()) {
        return pc.openElements.peek();
      }
      return null;
    }
    return tag.element;
  }

  private void flushWriteAfterTag(Writer w, HTMLParseContext pc) throws IOException {
    if (!pc.writeAfterTag.isEmpty()) {
      w.write(pc.writeAfterTag.toString());
      pc.writeAfterTag = new StringBuilder(1024);
    }
  }

  void saveComment(StringBuilder s, Writer w, HTMLParseContext pc) throws IOException {
    if (pc.onlyDetectingCharset || pc.expectingBadComment) {
      return;
    }
    trimCommentDelimiters(s);
    if (LOG.isTraceEnabled()) LOG.trace("Saving comment: {}", s);

    if (pc.inStyle || pc.inScript) {
      pc.currentStyleScriptChunk += s;
      return;
    }
    if (pc.killTag) {
      pc.killTag = false;
      return;
    }

    w.write(HtmlStrings.STR_COMMENT_PREFIX);
    w.write(escapeCommentContent(s));
    w.write(" -->");
  }

  private void trimCommentDelimiters(StringBuilder comment) {
    if ((comment.length() > 3)
        && (comment.charAt(0) == '!')
        && (comment.charAt(1) == '-')
        && (comment.charAt(2) == '-')) {
      comment.delete(0, 3);
      removeTrailingHyphen(comment);
      removeTrailingHyphen(comment);
    }
  }

  private void removeTrailingHyphen(StringBuilder comment) {
    if (comment.length() > 0 && comment.charAt(comment.length() - 1) == '-') {
      comment.setLength(comment.length() - 1);
    }
  }

  private String escapeCommentContent(CharSequence rawComment) {
    StringBuilder escaped = new StringBuilder(rawComment.length());
    for (int i = 0; i < rawComment.length(); i++) {
      char current = rawComment.charAt(i);
      if (current == '<') {
        escaped.append("&lt;");
      } else if (current == '>') {
        escaped.append("&gt;");
      } else {
        escaped.append(current);
      }
    }
    return escaped.toString();
  }

  static void throwFilterException(String msg) throws DataFilterException {
    // FIXME
    String longer = l10n("failedToParseLabel");
    throw new DataFilterException(longer, longer, msg);
  }

  public static class ParsedTag {
    public final String element;
    public final String[] unparsedAttrs;
    final boolean startSlash;
    final boolean endSlash;

    /*
     * public ParsedTag(ParsedTag t) { this.element = t.element;
     * this.unparsedAttrs = (String[]) t.unparsedAttrs.clone();
     * this.startSlash = t.startSlash; this.endSlash = t.endSlash; }
     */

    public ParsedTag(String elementName, Map<String, String> attributes) {
      this.element = elementName;
      startSlash = false;
      endSlash = true;
      String[] attrs = new String[attributes.size()];
      int pos = 0;
      for (Entry<String, String> entry : attributes.entrySet()) {
        attrs[pos++] = entry.getKey() + "=\"" + entry.getValue() + "\"";
      }
      this.unparsedAttrs = attrs;
    }

    public ParsedTag(ParsedTag t, String[] outAttrs) {
      this.element = t.element;
      this.unparsedAttrs = outAttrs;
      this.startSlash = t.startSlash;
      this.endSlash = t.endSlash;
    }

    public ParsedTag(ParsedTag t, Map<String, String> attributes) {
      String[] attrs = new String[attributes.size()];
      int pos = 0;
      for (Entry<String, String> entry : attributes.entrySet()) {
        attrs[pos++] = entry.getKey() + "=\"" + entry.getValue() + "\"";
      }
      this.element = t.element;
      this.unparsedAttrs = attrs;
      this.startSlash = t.startSlash;
      this.endSlash = t.endSlash;
    }

    public ParsedTag(List<String> v) {
      int len = v.size();
      if (len == 0) {
        element = null;
        unparsedAttrs = new String[0];
        startSlash = endSlash = false;
        return;
      }
      String s = v.get(len - 1);
      if (((len - 1 != 0) || (s.length() > 1)) && s.endsWith("/")) {
        s = s.substring(0, s.length() - 1);
        v.set(len - 1, s);
        if (s.isEmpty()) len--;
        endSlash = true;
        // Don't need to set it back because everything is an I-value
      } else endSlash = false;
      s = v.getFirst();
      if ((s.length() > 1) && s.startsWith("/")) {
        s = s.substring(1);
        v.set(0, s);
        startSlash = true;
      } else startSlash = false;
      element = v.getFirst();
      if (len > 1) {
        unparsedAttrs = new String[len - 1];
        for (int x = 1; x < len; x++) unparsedAttrs[x - 1] = v.get(x);
      } else unparsedAttrs = new String[0];
      if (LOG.isTraceEnabled()) LOG.trace("Element = " + element);
    }

    public ParsedTag sanitize(HTMLParseContext pc) throws DataFilterException {
      TagVerifier tv = allowedTagsVerifiers.get(element.toLowerCase());
      if (LOG.isTraceEnabled()) LOG.trace("Got verifier: " + tv + " for " + element);
      if (tv == null) {
        if (DELETE_WIERD_STUFF) {
          return null;
        } else {
          String err =
              HtmlStrings.STR_COMMENT_PREFIX
                  + HTMLEncoder.encode(l10n("unknownTag", "tag", element))
                  + " -->";
          if (!DELETE_ERRORS) throwFilterException(l10n("unknownTagLabel") + ' ' + err);
          return null;
        }
      }
      return tv.sanitize(this, pc);
    }

    @Override
    public String toString() {
      if (element == null) return "";
      StringBuilder sb = new StringBuilder("<");
      if (startSlash) sb.append('/');
      sb.append(element);
      if (unparsedAttrs != null) {
        int n = unparsedAttrs.length;
        for (int i = 0; i < n; i++) {
          sb.append(' ').append(unparsedAttrs[i]);
        }
      }
      if (endSlash) sb.append(" /");
      sb.append('>');
      return sb.toString();
    }

    public Map<String, String> getAttributesAsMap() {
      Map<String, String> map = new HashMap<>();
      for (String attr : unparsedAttrs) {
        String name = attr.substring(0, attr.indexOf('='));
        String value = attr.substring(attr.indexOf('=') + 2, attr.length() - 1);
        map.put(name, value);
      }
      return map;
    }

    public void htmlwrite(Writer w, HTMLParseContext pc) throws IOException {
      String s = toString();
      if (pc.getisXHTML()) {
        if (ElementInfo.isVoidElement(element) && s.charAt(s.length() - 2) != '/') {
          s = s.substring(0, s.length() - 1) + " />";
        }
      }
      if (s != null) {
        w.write(s);
      }
    }

    public void write(Writer w, HTMLParseContext pc) throws IOException {
      if (!startSlash) {
        if (ElementInfo.tryAutoClose(element) && element.equals(pc.peekTopElement()))
          pc.closeXHTMLTag(element, w);
        if (pc.getisXHTML() && !ElementInfo.isVoidElement(element)) pc.pushElementInStack(element);
        htmlwrite(w, pc);
      } else {
        if (pc.getisXHTML()) {
          pc.closeXHTMLTag(element, w);
        } else {
          htmlwrite(w, pc);
        }
      }
    }
  }

  public static Set<String> getAllowedHTMLTags() {
    return Collections.unmodifiableSet(allowedHTMLTags);
  }

  private static final Set<String> allowedHTMLTags = new HashSet<>();
  static final Map<String, TagVerifier> allowedTagsVerifiers =
      Collections.unmodifiableMap(getAllowedTagVerifiers());
  private static final String[] emptyStringArray = new String[0];

  private static Map<String, TagVerifier> getAllowedTagVerifiers() {
    Map<String, TagVerifier> allowedTagsVerifiers = new HashMap<>();

    allowedTagsVerifiers.put("?xml", new XmlTagVerifier());
    allowedTagsVerifiers.put("!doctype", new DocTypeTagVerifier("!doctype"));
    allowedTagsVerifiers.put("html", new HtmlTagVerifier());
    allowedTagsVerifiers.put(
        "head",
        new TagVerifier(
            "head",
            new String[] {"id"},
            // Don't support profiles.
            // We don't know what format they might be in, whether they will be parsed even though
            // they have bogus MIME types (which seems likely), etc.
            new String[] {
              /*"profile"*/
            },
            null,
            emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_TITLE, new TagVerifier(HtmlStrings.STR_TITLE, new String[] {"id"}));
    allowedTagsVerifiers.put("meta", new MetaTagVerifier());
    allowedTagsVerifiers.put(
        "body",
        new CoreTagVerifier(
            "body",
            new String[] {HtmlStrings.STR_BGCOLOR, "text", "link", "vlink", "alink"},
            null,
            new String[] {HtmlStrings.STR_BACKGROUND},
            new String[] {HtmlStrings.STR_ONLOAD, HtmlStrings.STR_ONUNLOAD},
            emptyStringArray));
    String[] group = {"div", "h1", "h2", "h3", "h4", "h5", "h6", "p", "caption"};
    for (String x : group)
      allowedTagsVerifiers.put(
          x,
          new CoreTagVerifier(
              x,
              new String[] {HtmlStrings.STR_ALIGN},
              emptyStringArray,
              emptyStringArray,
              emptyStringArray,
              emptyStringArray));
    String[] group2 = {
      "abbr",
      "acronym",
      "address",
      "article",
      "aside",
      "b",
      "bdi",
      "bdo",
      "big",
      "center",
      "cite",
      "code",
      "dd",
      "details",
      "dfn",
      "dt",
      "em",
      "fieldset",
      "figcaption",
      "figure",
      "footer",
      "header",
      "hgroup",
      "i",
      "kbd",
      "listing",
      "main",
      "mark",
      "nav",
      "noframes",
      // Delete <noscript> / </noscript>. So we can at least see the non-scripting code.
      // "noscript",
      "plaintext",
      "rp",
      "rt",
      "ruby",
      "s",
      "samp",
      HtmlStrings.STR_SECTION,
      "small",
      "span",
      "strike",
      "strong",
      "sub",
      "summary",
      "sup",
      "tt",
      "u",
      "var",
      "wbr",
      "xmp"
    };
    for (String x : group2)
      allowedTagsVerifiers.put(
          x,
          new CoreTagVerifier(
              x,
              emptyStringArray,
              emptyStringArray,
              emptyStringArray,
              emptyStringArray,
              emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_BLOCKQUOTE,
        new CoreTagVerifier(
            HtmlStrings.STR_BLOCKQUOTE,
            emptyStringArray,
            new String[] {"cite"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "q",
        new CoreTagVerifier(
            "q",
            emptyStringArray,
            new String[] {"cite"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "br",
        new BaseCoreTagVerifier(
            "br", new String[] {"clear"}, emptyStringArray, emptyStringArray, emptyStringArray));
    allowedTagsVerifiers.put(
        "pre",
        new CoreTagVerifier(
            "pre",
            new String[] {HtmlStrings.STR_WIDTH, HtmlStrings.STR_XML_SPACE},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "ins",
        new CoreTagVerifier(
            "ins",
            new String[] {"datetime"},
            new String[] {"cite"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "del",
        new CoreTagVerifier(
            "del",
            new String[] {"datetime"},
            new String[] {"cite"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "ul",
        new CoreTagVerifier(
            "ul",
            new String[] {"type", HtmlStrings.STR_COMPACT},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "ol",
        new CoreTagVerifier(
            "ol",
            new String[] {"type", HtmlStrings.STR_COMPACT, "start", "reversed"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "li",
        new CoreTagVerifier(
            "li",
            new String[] {"type", HtmlStrings.STR_VALUE},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "dl",
        new CoreTagVerifier(
            "dl",
            new String[] {HtmlStrings.STR_COMPACT},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "dir",
        new CoreTagVerifier(
            "dir",
            new String[] {HtmlStrings.STR_COMPACT},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "menu",
        new CoreTagVerifier(
            "menu",
            new String[] {HtmlStrings.STR_COMPACT},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_TABLE,
        new CoreTagVerifier(
            HtmlStrings.STR_TABLE,
            new String[] {
              "summary",
              HtmlStrings.STR_WIDTH,
              "border",
              HtmlStrings.STR_FRAME,
              "rules",
              "cellspacing",
              "cellpadding",
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_BGCOLOR
            },
            emptyStringArray,
            new String[] {HtmlStrings.STR_BACKGROUND},
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "thead",
        new CoreTagVerifier(
            "thead",
            new String[] {
              HtmlStrings.STR_ALIGN, "char", HtmlStrings.STR_CHAROFF, HtmlStrings.STR_VALIGN
            },
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "tfoot",
        new CoreTagVerifier(
            "tfoot",
            new String[] {
              HtmlStrings.STR_ALIGN, "char", HtmlStrings.STR_CHAROFF, HtmlStrings.STR_VALIGN
            },
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "tbody",
        new CoreTagVerifier(
            "tbody",
            new String[] {
              HtmlStrings.STR_ALIGN, "char", HtmlStrings.STR_CHAROFF, HtmlStrings.STR_VALIGN
            },
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "colgroup",
        new CoreTagVerifier(
            "colgroup",
            new String[] {
              "span",
              HtmlStrings.STR_WIDTH,
              HtmlStrings.STR_ALIGN,
              "char",
              HtmlStrings.STR_CHAROFF,
              HtmlStrings.STR_VALIGN
            },
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "col",
        new CoreTagVerifier(
            "col",
            new String[] {
              "span",
              HtmlStrings.STR_WIDTH,
              HtmlStrings.STR_ALIGN,
              "char",
              HtmlStrings.STR_CHAROFF,
              HtmlStrings.STR_VALIGN
            },
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "tr",
        new CoreTagVerifier(
            "tr",
            new String[] {
              HtmlStrings.STR_ALIGN,
              "char",
              HtmlStrings.STR_CHAROFF,
              HtmlStrings.STR_VALIGN,
              HtmlStrings.STR_BGCOLOR
            },
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "th",
        new CoreTagVerifier(
            "th",
            new String[] {
              "abbr",
              "axis",
              "headers",
              "scope",
              HtmlStrings.STR_ROWSPAN,
              "colspan",
              HtmlStrings.STR_ALIGN,
              "char",
              HtmlStrings.STR_CHAROFF,
              HtmlStrings.STR_VALIGN,
              "nowrap",
              HtmlStrings.STR_BGCOLOR,
              HtmlStrings.STR_WIDTH,
              HtmlStrings.STR_HEIGHT
            },
            emptyStringArray,
            new String[] {HtmlStrings.STR_BACKGROUND},
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "td",
        new CoreTagVerifier(
            "td",
            new String[] {
              "abbr",
              "axis",
              "headers",
              "scope",
              HtmlStrings.STR_ROWSPAN,
              "colspan",
              HtmlStrings.STR_ALIGN,
              "char",
              HtmlStrings.STR_CHAROFF,
              HtmlStrings.STR_VALIGN,
              "nowrap",
              HtmlStrings.STR_BGCOLOR,
              HtmlStrings.STR_WIDTH,
              HtmlStrings.STR_HEIGHT
            },
            emptyStringArray,
            new String[] {HtmlStrings.STR_BACKGROUND},
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "a",
        new LinkTagVerifier(
            "a",
            new String[] {
              HtmlStrings.STR_ACCESSKEY,
              HtmlStrings.STR_TABINDEX,
              "name",
              "shape",
              "coords",
              HtmlStrings.STR_TARGET
            },
            emptyStringArray,
            emptyStringArray,
            new String[] {HtmlStrings.STR_ONFOCUS, HtmlStrings.STR_ONBLUR}));
    allowedTagsVerifiers.put(
        "link",
        new LinkTagVerifier(
            "link",
            new String[] {HtmlStrings.STR_MEDIA, HtmlStrings.STR_TARGET},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "base",
        new BaseHrefTagVerifier(
            "base",
            new String[] {"id", HtmlStrings.STR_TARGET},
            new String[] {
              /* explicitly sanitized by class */
            }));
    allowedTagsVerifiers.put(
        "img",
        new CoreTagVerifier(
            "img",
            new String[] {
              "alt",
              "name",
              HtmlStrings.STR_HEIGHT,
              HtmlStrings.STR_WIDTH,
              "ismap",
              HtmlStrings.STR_ALIGN,
              "border",
              "hspace",
              "vspace"
            },
            new String[] {HtmlStrings.STR_LONGDESC, "usemap"},
            new String[] {"src"},
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "map",
        new CoreTagVerifier(
            "map",
            new String[] {"name"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "area",
        new CoreTagVerifier(
            "area",
            new String[] {
              HtmlStrings.STR_ACCESSKEY,
              HtmlStrings.STR_TABINDEX,
              "shape",
              "coords",
              "nohref",
              "alt",
              HtmlStrings.STR_TARGET
            },
            new String[] {"href"},
            emptyStringArray,
            new String[] {HtmlStrings.STR_ONFOCUS, HtmlStrings.STR_ONBLUR},
            emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_AUDIO, // currently just minimal support
        new MediaTagVerifier(
            HtmlStrings.STR_AUDIO,
            emptyStringArray,
            emptyStringArray, // uris
            new String[] {"src"}, // inline uris
            emptyStringArray,
            new String[] { // boolean attributes
              "preload", "controls", "loop"
            }));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_VIDEO, // currently just minimal support
        new MediaTagVerifier(
            HtmlStrings.STR_VIDEO,
            new String[] {HtmlStrings.STR_WIDTH, HtmlStrings.STR_HEIGHT},
            emptyStringArray, // uris
            new String[] {"src", "poster"}, // inline uris
            emptyStringArray,
            new String[] { // boolean attributes
              "preload", "controls", "loop"
            }));
    allowedTagsVerifiers.put(
        "source", // currently just minimal support
        new MediaTagVerifier(
            "source",
            emptyStringArray, // media is disallowed because it might leak device info, type is
            // disallowed because it could allow tricking a browser into
            // interpreting a file with another mime-type.
            emptyStringArray, // uris
            new String[] {"src"}, // inline uris
            emptyStringArray,
            emptyStringArray));
    // TODO: param tag?
    // http://www.w3.org/TR/html4/struct/objects.html#h-13.3.2
    // applet tag PROHIBITED - we do not support applets
    allowedTagsVerifiers.put(HtmlStrings.STR_STYLE, new StyleTagVerifier());
    allowedTagsVerifiers.put(
        "font",
        new BaseCoreTagVerifier(
            "font",
            new String[] {"size", "color", "face"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "basefont",
        new BaseCoreTagVerifier(
            "basefont",
            new String[] {"size", "color", "face"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "hr",
        new CoreTagVerifier(
            "hr",
            new String[] {HtmlStrings.STR_ALIGN, "noshade", "size", HtmlStrings.STR_WIDTH},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "frameset",
        new CoreTagVerifier(
            "frameset",
            new String[] {"rows", "cols"},
            emptyStringArray,
            emptyStringArray,
            new String[] {HtmlStrings.STR_ONLOAD, HtmlStrings.STR_ONUNLOAD},
            emptyStringArray,
            false));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_FRAME,
        new BaseCoreTagVerifier(
            HtmlStrings.STR_FRAME,
            new String[] {
              "name", "frameborder", "marginwidth", "marginheight", "noresize", "scrolling"
            },
            new String[] {HtmlStrings.STR_LONGDESC},
            new String[] {"src"},
            emptyStringArray));
    allowedTagsVerifiers.put(
        "iframe",
        new BaseCoreTagVerifier(
            "iframe",
            new String[] {
              "name",
              "frameborder",
              "marginwidth",
              "marginheight",
              "scrolling",
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_HEIGHT,
              HtmlStrings.STR_WIDTH
            },
            new String[] {HtmlStrings.STR_LONGDESC},
            new String[] {"src"},
            emptyStringArray));

    allowedTagsVerifiers.put(
        "form",
        new FormTagVerifier(
            "form",
            new String[] {"name"}, // FIXME add a whitelist filter for accept
            // All other attributes are handled by FormTagVerifier.
            new String[] {},
            new String[] {"onsubmit", "onreset"}));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_INPUT,
        new InputTagVerifier(
            HtmlStrings.STR_INPUT,
            new String[] {
              HtmlStrings.STR_ACCESSKEY,
              HtmlStrings.STR_TABINDEX,
              "type",
              "name",
              HtmlStrings.STR_VALUE,
              "checked",
              HtmlStrings.STR_DISABLED,
              "readonly",
              "size",
              "maxlength",
              "alt",
              "ismap",
              "accept",
              HtmlStrings.STR_ALIGN,
              "form"
            },
            new String[] {"usemap"},
            new String[] {"src"},
            new String[] {
              HtmlStrings.STR_ONFOCUS,
              HtmlStrings.STR_ONBLUR,
              HtmlStrings.STR_ONSELECT,
              HtmlStrings.STR_ONCHANGE
            }));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_BUTTON,
        new CoreTagVerifier(
            HtmlStrings.STR_BUTTON,
            new String[] {
              HtmlStrings.STR_ACCESSKEY,
              HtmlStrings.STR_TABINDEX,
              "name",
              HtmlStrings.STR_VALUE,
              "type",
              HtmlStrings.STR_DISABLED
            },
            emptyStringArray,
            emptyStringArray,
            new String[] {HtmlStrings.STR_ONFOCUS, HtmlStrings.STR_ONBLUR},
            emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_SELECT,
        new CoreTagVerifier(
            HtmlStrings.STR_SELECT,
            new String[] {
              "name", "size", "multiple", HtmlStrings.STR_DISABLED, HtmlStrings.STR_TABINDEX
            },
            emptyStringArray,
            emptyStringArray,
            new String[] {
              HtmlStrings.STR_ONFOCUS, HtmlStrings.STR_ONBLUR, HtmlStrings.STR_ONCHANGE
            },
            emptyStringArray));
    allowedTagsVerifiers.put(
        "optgroup",
        new CoreTagVerifier(
            "optgroup",
            new String[] {HtmlStrings.STR_DISABLED, HtmlStrings.STR_LABEL},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_OPTION,
        new CoreTagVerifier(
            HtmlStrings.STR_OPTION,
            new String[] {
              "selected", HtmlStrings.STR_DISABLED, HtmlStrings.STR_LABEL, HtmlStrings.STR_VALUE
            },
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "textarea",
        new CoreTagVerifier(
            "textarea",
            new String[] {
              HtmlStrings.STR_ACCESSKEY,
              HtmlStrings.STR_TABINDEX,
              "name",
              "rows",
              "cols",
              HtmlStrings.STR_DISABLED,
              "readonly"
            },
            emptyStringArray,
            emptyStringArray,
            new String[] {
              HtmlStrings.STR_ONFOCUS,
              HtmlStrings.STR_ONBLUR,
              HtmlStrings.STR_ONSELECT,
              HtmlStrings.STR_ONCHANGE
            },
            emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_METER,
        new CoreTagVerifier(
            HtmlStrings.STR_METER,
            new String[] {"form", "high", "low", "max", "min", "optimum", HtmlStrings.STR_VALUE},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "progress",
        new CoreTagVerifier(
            "progress",
            new String[] {"max", HtmlStrings.STR_VALUE},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "isindex",
        new BaseCoreTagVerifier(
            "isindex",
            new String[] {"prompt"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        HtmlStrings.STR_LABEL,
        new CoreTagVerifier(
            HtmlStrings.STR_LABEL,
            new String[] {"for", HtmlStrings.STR_ACCESSKEY},
            emptyStringArray,
            emptyStringArray,
            new String[] {HtmlStrings.STR_ONFOCUS, HtmlStrings.STR_ONBLUR},
            emptyStringArray));
    allowedTagsVerifiers.put(
        "legend",
        new CoreTagVerifier(
            "legend",
            new String[] {HtmlStrings.STR_ACCESSKEY, HtmlStrings.STR_ALIGN},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put("script", new ScriptTagVerifier());
    /* MathML 3.0 support for presentation markup, deprecated attributes
     * not included so don't try using them. xref not supported as it is
     * mainly used to link presentation and content in parallel markup.
     *
     * Content markup not supported as it is larger and presumably not
     * used that much, and **HAS SECURITY ISSUES**: Content markup uses
     * Content Dictionaries, which by default are loaded from a default
     * URL on the web.
     * See attributes: cdgroup, definitionURL, cd.
     * Elements: csymbol, annotation, annotation-xml. */
    allowedTagsVerifiers.put(
        "math",
        new CoreTagVerifier(
            "math",
            new String[] {
              HtmlStrings.STR_ACCENT,
              HtmlStrings.STR_ACCENTUNDER,
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_ALIGNMENTSCOPE,
              "altimg-height",
              "altimg-valign",
              "altimg-width",
              "alttext",
              HtmlStrings.STR_BEVELLED,
              HtmlStrings.STR_CHARALIGN,
              HtmlStrings.STR_CHARSPACING,
              HtmlStrings.STR_CLOSE,
              HtmlStrings.STR_COLUMNALIGN,
              HtmlStrings.STR_COLUMNLINES,
              HtmlStrings.STR_COLUMNSPACING,
              HtmlStrings.STR_COLUMNSPAN,
              HtmlStrings.STR_COLUMNWIDTH,
              HtmlStrings.STR_CROSSOUT,
              "decimalpoint",
              HtmlStrings.STR_DEPTH,
              HtmlStrings.STR_DENOMALIGN,
              "dir",
              "display",
              HtmlStrings.STR_DISPLAYSTYLE,
              "edge",
              HtmlStrings.STR_EQUALCOLUMNS,
              HtmlStrings.STR_EQUALROWS,
              HtmlStrings.STR_FENCE,
              "form",
              HtmlStrings.STR_FRAME,
              HtmlStrings.STR_FRAMESPACING,
              HtmlStrings.STR_GROUPALIGN,
              HtmlStrings.STR_HEIGHT,
              HtmlStrings.STR_INDENTALIGN,
              HtmlStrings.STR_INDENTALIGNFIRST,
              HtmlStrings.STR_INDENTALIGNLAST,
              HtmlStrings.STR_INDENTSHIFT,
              HtmlStrings.STR_INDENTSHIFTFIRST,
              HtmlStrings.STR_INDENTSHIFTLAST,
              HtmlStrings.STR_INDENTTARGET,
              "infixlinebreakstyle",
              HtmlStrings.STR_LARGEOP,
              HtmlStrings.STR_LEFTOVERHANG,
              HtmlStrings.STR_LENGTH,
              HtmlStrings.STR_LINEBREAK,
              HtmlStrings.STR_LINEBREAKMULTCHAR,
              HtmlStrings.STR_LINEBREAKSTYLE,
              HtmlStrings.STR_LINELEADING,
              HtmlStrings.STR_LOCATION,
              HtmlStrings.STR_LQUOTE,
              HtmlStrings.STR_LSPACE,
              HtmlStrings.STR_LINETHICKNESS,
              HtmlStrings.STR_LONGDIVSTYLE,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_MATHSIZE,
              HtmlStrings.STR_MATHVARIANT,
              HtmlStrings.STR_MAXSIZE,
              "maxwidth",
              HtmlStrings.STR_MINLABELSPACING,
              HtmlStrings.STR_MINSIZE,
              HtmlStrings.STR_MOVABLELIMITS,
              HtmlStrings.STR_MSLINETHICKNESS,
              HtmlStrings.STR_NOTATION,
              HtmlStrings.STR_NUMALIGN,
              "open",
              "overflow",
              HtmlStrings.STR_POSITION,
              HtmlStrings.STR_RIGHTOVERHANG,
              HtmlStrings.STR_ROWALIGN,
              HtmlStrings.STR_ROWLINES,
              HtmlStrings.STR_ROWSPACING,
              HtmlStrings.STR_ROWSPAN,
              HtmlStrings.STR_RQUOTE,
              HtmlStrings.STR_RSPACE,
              "scriptlevel",
              "scriptminsize",
              HtmlStrings.STR_SCRIPTSIZEMULTIPLIER,
              HtmlStrings.STR_SEPARATOR,
              HtmlStrings.STR_SEPARATORS,
              HtmlStrings.STR_SHIFT,
              "side",
              HtmlStrings.STR_STACKALIGN,
              HtmlStrings.STR_STRETCHY,
              HtmlStrings.STR_SUBSCRIPTSHIFT,
              HtmlStrings.STR_SUPERSCRIPTSHIFT,
              HtmlStrings.STR_SYMMETRIC,
              HtmlStrings.STR_VOFFSET,
              HtmlStrings.STR_WIDTH
            },
            new String[] {"href"},
            new String[] {"altimg"},
            emptyStringArray,
            emptyStringArray));
    // MathML Presentation tags follow
    String[] mathmlempty = {"mprescripts", "none"};
    for (String x : mathmlempty)
      allowedTagsVerifiers.put(
          x,
          new CoreTagVerifier(
              x,
              emptyStringArray,
              emptyStringArray,
              emptyStringArray,
              emptyStringArray,
              emptyStringArray));
    String[] mathmlpresent = {"merror", "mphantom", "mroot", "msqrt"};
    for (String x : mathmlpresent)
      allowedTagsVerifiers.put(
          x,
          new CoreTagVerifier(
              x,
              new String[] {HtmlStrings.STR_MATHBACKGROUND, HtmlStrings.STR_MATHCOLOR},
              new String[] {"href"},
              emptyStringArray,
              emptyStringArray,
              emptyStringArray));
    allowedTagsVerifiers.put(
        "msub",
        new CoreTagVerifier(
            "msub",
            new String[] {
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_SUBSCRIPTSHIFT
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "msup",
        new CoreTagVerifier(
            "msup",
            new String[] {
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_SUPERSCRIPTSHIFT
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    String[] mathmlscripts = {"msubsup", "mmultiscripts"};
    for (String x : mathmlscripts)
      allowedTagsVerifiers.put(
          x,
          new CoreTagVerifier(
              x,
              new String[] {
                HtmlStrings.STR_MATHBACKGROUND,
                HtmlStrings.STR_MATHCOLOR,
                HtmlStrings.STR_SUBSCRIPTSHIFT,
                HtmlStrings.STR_SUPERSCRIPTSHIFT
              },
              new String[] {"href"},
              emptyStringArray,
              emptyStringArray,
              emptyStringArray));
    allowedTagsVerifiers.put(
        "msrow",
        new CoreTagVerifier(
            "msrow",
            new String[] {
              HtmlStrings.STR_MATHBACKGROUND, HtmlStrings.STR_MATHCOLOR, HtmlStrings.STR_POSITION
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "msgroup",
        new CoreTagVerifier(
            "msgroup",
            new String[] {
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_POSITION,
              HtmlStrings.STR_SHIFT
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "menclose",
        new CoreTagVerifier(
            "menclose",
            new String[] {
              HtmlStrings.STR_MATHBACKGROUND, HtmlStrings.STR_MATHCOLOR, HtmlStrings.STR_NOTATION
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "msline",
        new CoreTagVerifier(
            "msline",
            new String[] {
              HtmlStrings.STR_LEFTOVERHANG,
              HtmlStrings.STR_LENGTH,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_MSLINETHICKNESS,
              HtmlStrings.STR_POSITION,
              HtmlStrings.STR_RIGHTOVERHANG
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "maligngroup",
        new CoreTagVerifier(
            "maligngroup",
            new String[] {
              HtmlStrings.STR_GROUPALIGN, HtmlStrings.STR_MATHBACKGROUND, HtmlStrings.STR_MATHCOLOR
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "malignmark",
        new CoreTagVerifier(
            "malignmark",
            new String[] {"edge", HtmlStrings.STR_MATHBACKGROUND, HtmlStrings.STR_MATHCOLOR},
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mrow",
        new CoreTagVerifier(
            "mrow",
            new String[] {"dir", HtmlStrings.STR_MATHBACKGROUND, HtmlStrings.STR_MATHCOLOR},
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    String[] mathmlitem = {"mi", "mn", "mtext"};
    for (String x : mathmlitem)
      allowedTagsVerifiers.put(
          x,
          new CoreTagVerifier(
              x,
              new String[] {
                "dir",
                HtmlStrings.STR_MATHBACKGROUND,
                HtmlStrings.STR_MATHCOLOR,
                HtmlStrings.STR_MATHSIZE,
                HtmlStrings.STR_MATHVARIANT
              },
              new String[] {"href"},
              emptyStringArray,
              emptyStringArray,
              emptyStringArray));
    allowedTagsVerifiers.put(
        "ms",
        new CoreTagVerifier(
            "ms",
            new String[] {
              "dir",
              HtmlStrings.STR_LQUOTE,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_MATHSIZE,
              HtmlStrings.STR_MATHVARIANT,
              HtmlStrings.STR_RQUOTE
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mpadded",
        new CoreTagVerifier(
            "mpadded",
            new String[] {
              HtmlStrings.STR_DEPTH,
              HtmlStrings.STR_HEIGHT,
              HtmlStrings.STR_LSPACE,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_VOFFSET,
              HtmlStrings.STR_WIDTH
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mspace",
        new CoreTagVerifier(
            "mspace",
            new String[] {
              HtmlStrings.STR_DEPTH,
              "dir",
              HtmlStrings.STR_HEIGHT,
              HtmlStrings.STR_INDENTALIGN,
              HtmlStrings.STR_INDENTALIGNFIRST,
              HtmlStrings.STR_INDENTALIGNLAST,
              HtmlStrings.STR_INDENTSHIFT,
              HtmlStrings.STR_INDENTSHIFTFIRST,
              HtmlStrings.STR_INDENTSHIFTLAST,
              HtmlStrings.STR_INDENTTARGET,
              HtmlStrings.STR_LINEBREAK,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_MATHSIZE,
              HtmlStrings.STR_MATHVARIANT,
              HtmlStrings.STR_WIDTH
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mscarry",
        new CoreTagVerifier(
            "mscarry",
            new String[] {
              HtmlStrings.STR_CROSSOUT,
              HtmlStrings.STR_LOCATION,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mscarries",
        new CoreTagVerifier(
            "mscarries",
            new String[] {
              HtmlStrings.STR_CROSSOUT,
              HtmlStrings.STR_LOCATION,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_POSITION,
              HtmlStrings.STR_SCRIPTSIZEMULTIPLIER
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    String[] mathmltr = {"mtr", "mlabeledtr"};
    for (String x : mathmltr)
      allowedTagsVerifiers.put(
          x,
          new CoreTagVerifier(
              x,
              new String[] {
                HtmlStrings.STR_COLUMNALIGN,
                HtmlStrings.STR_GROUPALIGN,
                HtmlStrings.STR_MATHBACKGROUND,
                HtmlStrings.STR_MATHCOLOR,
                HtmlStrings.STR_ROWALIGN
              },
              new String[] {"href"},
              emptyStringArray,
              emptyStringArray,
              emptyStringArray));
    allowedTagsVerifiers.put(
        "mtd",
        new CoreTagVerifier(
            "mtd",
            new String[] {
              HtmlStrings.STR_COLUMNALIGN,
              HtmlStrings.STR_COLUMNSPAN,
              HtmlStrings.STR_GROUPALIGN,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_ROWALIGN,
              HtmlStrings.STR_ROWSPAN
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mfenced",
        new CoreTagVerifier(
            "mfenced",
            new String[] {
              HtmlStrings.STR_CLOSE,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              "open",
              HtmlStrings.STR_SEPARATORS
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mfrac",
        new CoreTagVerifier(
            "mfrac",
            new String[] {
              HtmlStrings.STR_BEVELLED,
              HtmlStrings.STR_DENOMALIGN,
              HtmlStrings.STR_LINETHICKNESS,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_NUMALIGN
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mglyph",
        new CoreTagVerifier(
            "mglyph",
            new String[] {
              "alt",
              HtmlStrings.STR_HEIGHT,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_VALIGN,
              HtmlStrings.STR_WIDTH
            },
            new String[] {"href"},
            new String[] {"src"},
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mstack",
        new CoreTagVerifier(
            "mstack",
            new String[] {
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_CHARALIGN,
              HtmlStrings.STR_CHARSPACING,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_STACKALIGN
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mlongdiv",
        new CoreTagVerifier(
            "mlongdiv",
            new String[] {
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_CHARALIGN,
              HtmlStrings.STR_CHARSPACING,
              HtmlStrings.STR_LONGDIVSTYLE,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_STACKALIGN
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mtable",
        new CoreTagVerifier(
            "mtable",
            new String[] {
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_ALIGNMENTSCOPE,
              HtmlStrings.STR_COLUMNALIGN,
              HtmlStrings.STR_COLUMNLINES,
              HtmlStrings.STR_COLUMNSPACING,
              HtmlStrings.STR_COLUMNWIDTH,
              HtmlStrings.STR_DISPLAYSTYLE,
              HtmlStrings.STR_EQUALCOLUMNS,
              HtmlStrings.STR_EQUALROWS,
              HtmlStrings.STR_FRAME,
              HtmlStrings.STR_FRAMESPACING,
              HtmlStrings.STR_GROUPALIGN,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_MINLABELSPACING,
              HtmlStrings.STR_ROWALIGN,
              HtmlStrings.STR_ROWLINES,
              HtmlStrings.STR_ROWSPACING,
              "side",
              HtmlStrings.STR_WIDTH
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "munder",
        new CoreTagVerifier(
            "munder",
            new String[] {
              HtmlStrings.STR_ACCENTUNDER,
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mo",
        new CoreTagVerifier(
            "mo",
            new String[] {
              HtmlStrings.STR_ACCENT,
              "dir",
              HtmlStrings.STR_FENCE,
              "form",
              HtmlStrings.STR_INDENTALIGN,
              HtmlStrings.STR_INDENTALIGNFIRST,
              HtmlStrings.STR_INDENTALIGNLAST,
              HtmlStrings.STR_INDENTSHIFT,
              HtmlStrings.STR_INDENTSHIFTFIRST,
              HtmlStrings.STR_INDENTSHIFTLAST,
              HtmlStrings.STR_INDENTTARGET,
              HtmlStrings.STR_LARGEOP,
              HtmlStrings.STR_LINEBREAK,
              HtmlStrings.STR_LINEBREAKMULTCHAR,
              HtmlStrings.STR_LINEBREAKSTYLE,
              HtmlStrings.STR_LINELEADING,
              HtmlStrings.STR_LSPACE,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_MATHSIZE,
              HtmlStrings.STR_MATHVARIANT,
              HtmlStrings.STR_MAXSIZE,
              HtmlStrings.STR_MINSIZE,
              HtmlStrings.STR_MOVABLELIMITS,
              HtmlStrings.STR_RSPACE,
              HtmlStrings.STR_SEPARATOR,
              HtmlStrings.STR_STRETCHY,
              HtmlStrings.STR_SYMMETRIC
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mover",
        new CoreTagVerifier(
            "mover",
            new String[] {
              HtmlStrings.STR_ACCENT,
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "munderover",
        new CoreTagVerifier(
            "munderover",
            new String[] {
              HtmlStrings.STR_ACCENT,
              HtmlStrings.STR_ACCENTUNDER,
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    allowedTagsVerifiers.put(
        "mstyle",
        new CoreTagVerifier(
            "mstyle",
            new String[] {
              HtmlStrings.STR_ACCENT,
              HtmlStrings.STR_ACCENTUNDER,
              HtmlStrings.STR_ALIGN,
              HtmlStrings.STR_ALIGNMENTSCOPE,
              HtmlStrings.STR_BEVELLED,
              HtmlStrings.STR_CHARALIGN,
              HtmlStrings.STR_CHARSPACING,
              HtmlStrings.STR_CLOSE,
              HtmlStrings.STR_COLUMNALIGN,
              HtmlStrings.STR_COLUMNLINES,
              HtmlStrings.STR_COLUMNSPACING,
              HtmlStrings.STR_COLUMNSPAN,
              HtmlStrings.STR_COLUMNWIDTH,
              HtmlStrings.STR_CROSSOUT,
              "decimalpoint",
              HtmlStrings.STR_DEPTH,
              HtmlStrings.STR_DENOMALIGN,
              "dir",
              HtmlStrings.STR_DISPLAYSTYLE,
              "edge",
              HtmlStrings.STR_EQUALCOLUMNS,
              HtmlStrings.STR_EQUALROWS,
              HtmlStrings.STR_FENCE,
              "form",
              HtmlStrings.STR_FRAME,
              HtmlStrings.STR_FRAMESPACING,
              HtmlStrings.STR_GROUPALIGN,
              HtmlStrings.STR_HEIGHT,
              HtmlStrings.STR_INDENTALIGN,
              HtmlStrings.STR_INDENTALIGNFIRST,
              HtmlStrings.STR_INDENTALIGNLAST,
              HtmlStrings.STR_INDENTSHIFT,
              HtmlStrings.STR_INDENTSHIFTFIRST,
              HtmlStrings.STR_INDENTSHIFTLAST,
              HtmlStrings.STR_INDENTTARGET,
              "infixlinebreakstyle",
              HtmlStrings.STR_LARGEOP,
              HtmlStrings.STR_LEFTOVERHANG,
              HtmlStrings.STR_LENGTH,
              HtmlStrings.STR_LINEBREAK,
              HtmlStrings.STR_LINEBREAKMULTCHAR,
              HtmlStrings.STR_LINEBREAKSTYLE,
              HtmlStrings.STR_LINELEADING,
              HtmlStrings.STR_LOCATION,
              HtmlStrings.STR_LQUOTE,
              HtmlStrings.STR_LSPACE,
              HtmlStrings.STR_LINETHICKNESS,
              HtmlStrings.STR_LONGDIVSTYLE,
              HtmlStrings.STR_MATHBACKGROUND,
              HtmlStrings.STR_MATHCOLOR,
              HtmlStrings.STR_MATHSIZE,
              HtmlStrings.STR_MATHVARIANT,
              HtmlStrings.STR_MAXSIZE,
              HtmlStrings.STR_MINLABELSPACING,
              HtmlStrings.STR_MINSIZE,
              HtmlStrings.STR_MOVABLELIMITS,
              HtmlStrings.STR_MSLINETHICKNESS,
              HtmlStrings.STR_NOTATION,
              HtmlStrings.STR_NUMALIGN,
              "open",
              HtmlStrings.STR_POSITION,
              HtmlStrings.STR_RIGHTOVERHANG,
              HtmlStrings.STR_ROWALIGN,
              HtmlStrings.STR_ROWLINES,
              HtmlStrings.STR_ROWSPACING,
              HtmlStrings.STR_ROWSPAN,
              HtmlStrings.STR_RQUOTE,
              HtmlStrings.STR_RSPACE,
              "scriptlevel",
              "scriptminsize",
              HtmlStrings.STR_SCRIPTSIZEMULTIPLIER,
              HtmlStrings.STR_SEPARATOR,
              HtmlStrings.STR_SEPARATORS,
              HtmlStrings.STR_SHIFT,
              "side",
              HtmlStrings.STR_STACKALIGN,
              HtmlStrings.STR_STRETCHY,
              HtmlStrings.STR_SUBSCRIPTSHIFT,
              HtmlStrings.STR_SUPERSCRIPTSHIFT,
              HtmlStrings.STR_SYMMETRIC,
              HtmlStrings.STR_VOFFSET,
              HtmlStrings.STR_WIDTH
            },
            new String[] {"href"},
            emptyStringArray,
            emptyStringArray,
            emptyStringArray));
    // <maction> would go here though it seems a bit pointless and may require extra filtering
    // MathML content tags would go here if anyone used them

    return allowedTagsVerifiers;
  }

  static class TagVerifier {

    // Attributes which need no sanitation
    private final HashSet<String> allowedAttrs;
    // Attributes which will be sanitized by child classes
    protected final HashSet<String> parsedAttrs;
    private final HashSet<String> uriAttrs;
    private final HashSet<String> inlineURIAttrs;
    final HashSet<String> booleanAttrs;
    private final HashSet<String> allowedRole;

    TagVerifier(String tag, String[] allowedAttrs) {
      this(tag, allowedAttrs, null, null, null);
    }

    TagVerifier(
        String tag,
        String[] allowedAttrs,
        String[] uriAttrs,
        String[] inlineURIAttrs,
        String[] booleanAttrs) {
      this.allowedAttrs = new HashSet<>();
      this.parsedAttrs = new HashSet<>();
      if (allowedAttrs != null) {
        this.allowedAttrs.addAll(Arrays.asList(allowedAttrs));
      }
      this.uriAttrs = new HashSet<>();
      if (uriAttrs != null) {
        this.uriAttrs.addAll(Arrays.asList(uriAttrs));
      }
      this.inlineURIAttrs = new HashSet<>();
      if (inlineURIAttrs != null) {
        this.inlineURIAttrs.addAll(Arrays.asList(inlineURIAttrs));
      }
      this.booleanAttrs = new HashSet<>();
      if (booleanAttrs != null) {
        this.booleanAttrs.addAll(Arrays.asList(booleanAttrs));
      }
      // https://w3c.github.io/aria/
      this.allowedRole =
          new HashSet<>(
              Arrays.asList(
                  "alert",
                  "alertdialog",
                  "application",
                  "article",
                  "banner",
                  HtmlStrings.STR_BLOCKQUOTE,
                  HtmlStrings.STR_BUTTON,
                  "caption",
                  "cell",
                  "checkbox",
                  "code",
                  "columnheader",
                  "combobox",
                  "command",
                  "comment",
                  "complementary",
                  "composite",
                  "contentinfo",
                  "definition",
                  "deletion",
                  "dialog",
                  "directory",
                  "document",
                  "emphasis",
                  "feed",
                  "figure",
                  "form",
                  "generic",
                  "grid",
                  "gridcell",
                  "group",
                  "heading",
                  "image",
                  "img",
                  HtmlStrings.STR_INPUT,
                  "insertion",
                  "landmark",
                  "link",
                  "list",
                  "listbox",
                  "listitem",
                  "log",
                  "main",
                  "mark",
                  "marquee",
                  "math",
                  "menu",
                  "menubar",
                  "menuitem",
                  "menuitemcheckbox",
                  "menuitemradio",
                  HtmlStrings.STR_METER,
                  "navigation",
                  "none",
                  "note",
                  HtmlStrings.STR_OPTION,
                  "paragraph",
                  "presentation",
                  "progressbar",
                  "radio",
                  "radiogroup",
                  "range",
                  "region",
                  "roletype",
                  "row",
                  "rowgroup",
                  "rowheader",
                  "scrollbar",
                  "search",
                  "searchbox",
                  HtmlStrings.STR_SECTION,
                  "sectionhead",
                  HtmlStrings.STR_SELECT,
                  HtmlStrings.STR_SEPARATOR,
                  "slider",
                  "spinbutton",
                  "status",
                  "strong",
                  "structure",
                  "subscript",
                  "suggestion",
                  "superscript",
                  "switch",
                  "tab",
                  HtmlStrings.STR_TABLE,
                  "tablist",
                  "tabpanel",
                  "term",
                  "textbox",
                  "time",
                  "timer",
                  "toolbar",
                  "tooltip",
                  "tree",
                  "treegrid",
                  "treeitem",
                  "widget",
                  "window"));
    }

    ParsedTag sanitize(ParsedTag t, HTMLParseContext pc) throws DataFilterException {
      Map<String, Object> attributes = buildAttributeMap(t);
      Map<String, Object> sanitized = sanitizeHash(attributes, t, pc);
      if (sanitized == null) {
        return null;
      }
      removeBlankEntries(sanitized, pc.isXHTML);
      if (sanitized.isEmpty() && expungeTagIfNoAttributes()) {
        return null;
      }
      if (t.startSlash) {
        return new ParsedTag(t, (String[]) null);
      }
      return buildSanitizedTag(t, sanitized);
    }

    private Map<String, Object> buildAttributeMap(ParsedTag tag) {
      Map<String, Object> attributes = new LinkedHashMap<>();
      boolean waitingForValue = false;
      String previousKey = "";
      if (tag.unparsedAttrs == null) {
        return attributes;
      }
      for (String rawAttribute : tag.unparsedAttrs) {
        if (waitingForValue) {
          waitingForValue = false;
          previousKey = applyDeferredValue(attributes, previousKey, rawAttribute);
          continue;
        }
        AttributeToken token = parseAttributeToken(rawAttribute, previousKey);
        waitingForValue = token.expectingValue;
        previousKey = token.key;
        if (token.value != null) {
          attributes.put(token.key, token.value);
        } else if (!waitingForValue) {
          attributes.put(token.key, new Object());
        }
      }
      return attributes;
    }

    private AttributeToken parseAttributeToken(String rawAttribute, String previousKey) {
      AttributeToken token = new AttributeToken();
      int separatorIndex = rawAttribute.indexOf('=');
      if (separatorIndex == rawAttribute.length() - 1) {
        token.expectingValue = true;
        token.key = separatorIndex == 0 ? previousKey : rawAttribute.substring(0, separatorIndex);
        token.key = token.key.toLowerCase();
        return token;
      }
      if (separatorIndex > -1) {
        String key = rawAttribute.substring(0, separatorIndex);
        if (key.isEmpty()) {
          key = previousKey;
        }
        token.key = key.toLowerCase();
        String rawValue = rawAttribute.substring(separatorIndex + 1);
        token.value = stripQuotes(rawValue);
        return token;
      }
      token.key = rawAttribute;
      return token;
    }

    private String applyDeferredValue(Map<String, Object> attributes, String key, String rawValue) {
      String sanitizedValue = stripQuotes(rawValue);
      attributes.remove(key);
      attributes.put(key, sanitizedValue);
      return "";
    }

    private void removeBlankEntries(Map<String, Object> attributes, boolean isXhtml) {
      attributes
          .entrySet()
          .removeIf(entry -> entry.getValue() == null || entry.getValue().equals("") && isXhtml);
    }

    private ParsedTag buildSanitizedTag(ParsedTag source, Map<String, Object> attributes) {
      String[] outAttrs = new String[attributes.size()];
      int index = 0;
      for (Map.Entry<String, Object> entry : attributes.entrySet()) {
        String name = entry.getKey();
        Object value = entry.getValue();
        StringBuilder buffer = new StringBuilder(name);
        if (value instanceof String stringValue) {
          buffer.append("=\"").append(stringValue).append('"');
        }
        outAttrs[index++] = buffer.toString();
      }
      return new ParsedTag(source, outAttrs);
    }

    private static final class AttributeToken {
      boolean expectingValue;
      String key;
      String value;
    }

    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = new LinkedHashMap<>();
      for (Map.Entry<String, Object> entry : h.entrySet()) {
        String name = entry.getKey();
        Object value = entry.getValue();
        if (LOG.isDebugEnabled()) {
          LOG.debug("HTML Filter is sanitizing: {} = {}", name, value);
        }

        if (sanitizeUriAttribute(name, value, hn, pc)) {
          continue;
        }
        if (parsedAttrs.contains(name)) {
          hn.put(name, null);
          continue;
        }
        if (allowedAttrs.contains(name)) {
          hn.put(name, value);
          continue;
        }
        if (handleBooleanAttribute(name, value, hn, pc)) {
          continue;
        }
        if (handleLanguageAttribute(name, value, hn)) {
          continue;
        }
        handleRoleAttribute(name, value, hn);
      }
      return hn;
    }

    private boolean sanitizeUriAttribute(
        String name, Object value, Map<String, Object> output, HTMLParseContext pc)
        throws DataFilterException {
      boolean inline = inlineURIAttrs.contains(name);
      if (!inline && !uriAttrs.contains(name)) {
        return false;
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug("{} URI attribute: {}", inline ? "Inline" : "Non-inline", name);
      }
      Object sanitized = value;
      if (value instanceof String uri) {
        uri = HTMLDecoder.decode(uri);
        uri = htmlSanitizeURI(uri, null, null, null, pc.cb, pc, inline);
        if (uri == null) {
          return true;
        }
        sanitized = HTMLEncoder.encode(uri);
      }
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "HTML Filter is putting {} uri attribute: {} = {}",
            inline ? "inline" : "",
            name,
            sanitized);
      }
      output.put(name, sanitized);
      return true;
    }

    private boolean handleBooleanAttribute(
        String name, Object value, Map<String, Object> output, HTMLParseContext pc) {
      if (!booleanAttrs.contains(name)) {
        return false;
      }
      String stringValue = value instanceof String ? (String) value : null;
      if ((stringValue != null && stringValue.equalsIgnoreCase(name))
          || (!pc.isXHTML && value == null)) {
        output.put(name, value);
      }
      return true;
    }

    private boolean handleLanguageAttribute(String name, Object value, Map<String, Object> output) {
      if (value == null) {
        return false;
      }
      if ("xml:lang".equals(name) || "lang".equals(name)) {
        if (LOG.isTraceEnabled()) {
          LOG.trace("HTML Filter is putting attribute: {} = {}", name, value);
        }
        output.put(name, value);
        return true;
      }
      if ("dir".equals(name) && value instanceof String stringValue) {
        if (stringValue.equalsIgnoreCase("ltr")
            || stringValue.equalsIgnoreCase("rtl")
            || stringValue.equalsIgnoreCase("auto")) {
          if (LOG.isTraceEnabled()) {
            LOG.trace("HTML Filter is putting attribute: {} = {}", name, value);
          }
          output.put(name, value);
        }
        return true;
      }
      return false;
    }

    private void handleRoleAttribute(String name, Object value, Map<String, Object> output) {
      if (!"role".equals(name) || !(value instanceof String stringValue)) {
        return;
      }
      if (allowedRole.contains(stringValue)) {
        output.put(name, value);
      }
    }

    /*If this function returns true, this tag will be removed from
     * the sanitized output if it has no attributes*/
    protected boolean expungeTagIfNoAttributes() {
      return false;
    }
  }

  static String stripQuotes(String s) {
    final String quotes = "\"'";
    if (s.length() >= 2) {
      int n = quotes.length();
      for (int x = 0; x < n; x++) {
        char cc = quotes.charAt(x);
        if ((s.charAt(0) == cc) && (s.charAt(s.length() - 1) == cc)) {
          if (s.length() > 2) s = s.substring(1, s.length() - 1);
          else s = "";
          break;
        }
      }
    }
    return s;
  }

  //	static String[] titleString = new String[] {HtmlStrings.STR_TITLE};

  abstract static class ScriptStyleTagVerifier extends TagVerifier {
    ScriptStyleTagVerifier(String tag, String[] allowedAttrs, String[] uriAttrs) {
      super(tag, allowedAttrs, uriAttrs, null, null);
    }

    abstract void setStyle(boolean b, HTMLParseContext pc);

    abstract boolean getStyle(HTMLParseContext pc);

    abstract void processStyle(HTMLParseContext pc);

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      if (p.startSlash) {
        return finish(h, hn, pc);
      } else {
        return start(h, hn, pc);
      }
    }

    Map<String, Object> finish(Map<String, Object> h, Map<String, Object> hn, HTMLParseContext pc)
        throws DataFilterException {
      if (LOG.isTraceEnabled()) LOG.trace("Finishing script/style");
      // Finishing
      setStyle(false, pc);
      pc.styleScriptRecurseCount--;
      if (pc.styleScriptRecurseCount < 0) {
        if (DELETE_ERRORS)
          pc.writeAfterTag
              .append(HtmlStrings.STR_COMMENT_PREFIX)
              .append(l10n("tooManyNestedStyleOrScriptTags"))
              .append(" -->");
        else throwFilterException(l10n("tooManyNestedStyleOrScriptTagsLong"));
        return null;
      }
      if (!pc.killStyle) {
        processStyle(pc);
        pc.writeStyleScriptWithTag = true;
      } else {
        pc.killStyle = false;
        pc.currentStyleScriptChunk = "";
      }
      pc.expectingBadComment = false;
      // Pass it on, no params for </style>
      return hn;
    }

    Map<String, Object> start(Map<String, Object> h, Map<String, Object> hn, HTMLParseContext pc)
        throws DataFilterException {
      if (LOG.isTraceEnabled()) LOG.trace("Starting script/style");
      pc.styleScriptRecurseCount++;
      if (pc.styleScriptRecurseCount > 1) {
        if (DELETE_ERRORS)
          pc.writeAfterTag
              .append(HtmlStrings.STR_COMMENT_PREFIX)
              .append(l10n("tooManyNestedStyleOrScriptTags"))
              .append(" -->");
        else throwFilterException(l10n("tooManyNestedStyleOrScriptTagsLong"));
        return null;
      }
      setStyle(true, pc);
      String type = getHashString(h, "type");
      if (type != null) {
        if (!type.equalsIgnoreCase(HtmlStrings.STR_TEXT_CSS) /* FIXME */) {
          pc.killStyle = true;
          pc.expectingBadComment = true;
          return null; // kill the tag
        }
        hn.put("type", HtmlStrings.STR_TEXT_CSS);
      }
      return hn;
    }
  }

  static class StyleTagVerifier extends ScriptStyleTagVerifier {
    StyleTagVerifier() {
      super(
          HtmlStrings.STR_STYLE,
          new String[] {
            "id", HtmlStrings.STR_MEDIA, HtmlStrings.STR_TITLE, HtmlStrings.STR_XML_SPACE
          },
          emptyStringArray);
    }

    @Override
    void setStyle(boolean b, HTMLParseContext pc) {
      pc.inStyle = b;
    }

    @Override
    boolean getStyle(HTMLParseContext pc) {
      return pc.inStyle;
    }

    @Override
    void processStyle(HTMLParseContext pc) {
      try {
        pc.currentStyleScriptChunk = sanitizeStyle(pc.currentStyleScriptChunk, pc.cb, pc, false);
      } catch (DataFilterException e) {
        LOG.error("Error parsing style: " + e, e);
        pc.currentStyleScriptChunk = "";
      }
    }
  }

  static class ScriptTagVerifier extends ScriptStyleTagVerifier {
    ScriptTagVerifier() {
      super(
          "script",
          new String[] {
            "id", HtmlStrings.STR_CHARSET, "type", "language", "defer", HtmlStrings.STR_XML_SPACE
          },
          new String[] {"src"});
      /*
       * FIXME: src not supported type ignored (we will need to check
       * this when if/when we support scripts charset ignored
       */
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> hn, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      // Call parent so we swallow the scripting
      super.sanitizeHash(hn, p, pc);
      return null; // Lose the tags
    }

    @Override
    void setStyle(boolean b, HTMLParseContext pc) {
      pc.inScript = b;
    }

    @Override
    boolean getStyle(HTMLParseContext pc) {
      return pc.inScript;
    }

    @Override
    void processStyle(HTMLParseContext pc) {
      pc.currentStyleScriptChunk = sanitizeScripting(pc.currentStyleScriptChunk);
    }
  }

  static class BaseCoreTagVerifier extends TagVerifier {
    private static final String[] locallyVerifiedAttrs =
        new String[] {"id", HtmlStrings.STR_CLASS, HtmlStrings.STR_STYLE};

    BaseCoreTagVerifier(
        String tag,
        String[] allowedAttrs,
        String[] uriAttrs,
        String[] inlineURIAttrs,
        String[] booleanAttrs) {
      super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, booleanAttrs);
      allowedHTMLTags.add(tag);
      this.parsedAttrs.addAll(Arrays.asList(locallyVerifiedAttrs));
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      // %i18n dealt with by TagVerifier
      // %coreattrs
      String id = getHashString(h, "id");
      if (id != null) {
        hn.put("id", id);
        // hopefully nobody will be stupid enough to encode URLs into
        // the unique ID... :)
      }
      String classNames = getHashString(h, HtmlStrings.STR_CLASS);
      if (classNames != null) {
        hn.put(HtmlStrings.STR_CLASS, classNames);
        // ditto
      }
      String style = getHashString(h, HtmlStrings.STR_STYLE);
      if (style != null) {
        style = sanitizeStyle(style, pc.cb, pc, true);
        if (style != null) style = escapeQuotes(style);
        if (style != null) hn.put(HtmlStrings.STR_STYLE, style);
      }
      String title = getHashString(h, HtmlStrings.STR_TITLE);
      if (title != null) {
        // PARANOIA: title is PLAIN TEXT, right? In all user agents? :)
        hn.put(HtmlStrings.STR_TITLE, title);
      }
      return hn;
    }
  }

  static class CoreTagVerifier extends BaseCoreTagVerifier {
    private final HashSet<String> eventAttrs;
    private static final String[] stdEvents =
        new String[] {
          "onclick",
          "ondblclick",
          "onmousedown",
          "onmouseup",
          "onmouseover",
          "onmousemove",
          "onmouseout",
          "onkeypress",
          "onkeydown",
          "onkeyup",
          HtmlStrings.STR_ONLOAD,
          HtmlStrings.STR_ONFOCUS,
          HtmlStrings.STR_ONBLUR,
          "oncontextmenu",
          "onresize",
          "onscroll",
          HtmlStrings.STR_ONUNLOAD,
          "onmouseenter",
          HtmlStrings.STR_ONCHANGE,
          "onreset",
          HtmlStrings.STR_ONSELECT,
          "onsubmit",
          "onerror",
        };

    CoreTagVerifier(
        String tag,
        String[] allowedAttrs,
        String[] uriAttrs,
        String[] inlineURIAttrs,
        String[] eventAttrs,
        String[] booleanAttrs) {
      this(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, booleanAttrs, true);
    }

    CoreTagVerifier(
        String tag,
        String[] allowedAttrs,
        String[] uriAttrs,
        String[] inlineURIAttrs,
        String[] eventAttrs,
        String[] booleanAttrs,
        boolean addStdEvents) {
      super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, booleanAttrs);
      this.eventAttrs = new HashSet<>();
      if (eventAttrs != null) {
        for (String eventAttr : eventAttrs) {
          this.eventAttrs.add(eventAttr);
          this.parsedAttrs.add(eventAttr);
        }
      }
      if (addStdEvents) {
        for (String stdEvent : stdEvents) {
          this.eventAttrs.add(stdEvent);
          this.parsedAttrs.add(stdEvent);
        }
      }
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      // events (default and added)
      for (String name : eventAttrs) {
        String arg = getHashString(h, name);
        if (arg != null) {
          arg = sanitizeScripting(arg);
          if (arg != null) hn.put(name, arg);
        }
      }

      return hn;
    }
  }

  static class LinkTagVerifier extends CoreTagVerifier {
    private static final String[] locallyVerifiedAttrs =
        new String[] {
          "type",
          HtmlStrings.STR_CHARSET,
          "rel",
          "rev",
          HtmlStrings.STR_MEDIA,
          HtmlStrings.STR_HREFLANG,
          "href"
        };

    LinkTagVerifier(
        String tag,
        String[] allowedAttrs,
        String[] uriAttrs,
        String[] inlineURIAttrs,
        String[] eventAttrs) {
      super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, null);
      this.parsedAttrs.addAll(Arrays.asList(locallyVerifiedAttrs));
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      LinkCharsetInfo charsetInfo = resolveLinkCharset(h);
      RelParseResult relResult = parseRelValue(getHashString(h, "rel"));
      if (relResult == null) {
        return null;
      }
      String parsedRev = normalizeRevValue(getHashString(h, "rev"));
      if (!relResult.normalizedRel.isEmpty()) {
        hn.put("rel", relResult.normalizedRel);
      }
      if (!parsedRev.isEmpty()) {
        hn.put("rev", parsedRev);
      }
      if (!relResult.isStylesheet && relResult.originalRel == null) {
        if (charsetInfo.type != null && charsetInfo.type.startsWith(HtmlStrings.STR_TEXT_CSS)) {
          return null;
        }
      }
      String fallbackCharset = null;
      if (relResult.isStylesheet) {
        fallbackCharset = charsetInfo.charset == null ? pc.charset : null;
        if (!handleStylesheetMetadata(h, hn, charsetInfo)) {
          return null;
        }
      }
      sanitizeHrefAttribute(
          h,
          hn,
          charsetInfo,
          fallbackCharset,
          relResult.isIcon,
          getHashString(h, HtmlStrings.STR_HREFLANG),
          pc);
      return hn;
    }

    private LinkCharsetInfo resolveLinkCharset(Map<String, Object> attributes) {
      LinkCharsetInfo info = new LinkCharsetInfo();
      info.type = getHashString(attributes, "type");
      if (info.type != null) {
        String[] typesplit = splitType(info.type);
        info.type = typesplit[0];
        if (typesplit[1] != null && !typesplit[1].isEmpty()) {
          info.charset = typesplit[1];
        }
        if (LOG.isTraceEnabled()) {
          LOG.trace("Processing link tag, type={}, charset={}", info.type, info.charset);
        }
      }
      String declaredCharset = getHashString(attributes, HtmlStrings.STR_CHARSET);
      if (declaredCharset != null) {
        info.charset = declaredCharset;
      }
      if (info.charset != null) {
        try {
          info.charset = URLDecoder.decode(info.charset, false);
        } catch (URLEncodedFormatException e) {
          info.charset = null;
        }
      }
      if (info.charset != null && info.charset.indexOf('&') != -1) {
        info.charset = null;
      }
      if (info.charset != null && !Charset.isSupported(info.charset)) {
        info.charset = null;
      }
      return info;
    }

    private RelParseResult parseRelValue(String rel) {
      if (rel == null) {
        return new RelParseResult(null, "", false, false);
      }
      String lowercase = rel.toLowerCase();
      StringTokenizer tok = new StringTokenizer(lowercase, " ");
      int index = 0;
      String previousToken = null;
      StringBuilder builder = new StringBuilder(lowercase.length());
      boolean stylesheet = false;
      boolean icon = false;
      while (tok.hasMoreTokens()) {
        String token = tok.nextToken();
        if ("stylesheet".equalsIgnoreCase(token)) {
          stylesheet = true;
          if (!isValidStylesheetPosition(index, previousToken)) {
            return null;
          }
          if (tok.hasMoreTokens()) {
            return null;
          }
        } else if ("icon".equalsIgnoreCase(token)) {
          icon = true;
        } else if (!isStandardLinkType(token)) {
          continue;
        }
        appendToken(builder, token);
        previousToken = token;
        index++;
      }
      return new RelParseResult(rel, builder.toString(), stylesheet, icon);
    }

    private boolean isValidStylesheetPosition(int index, String previousToken) {
      return index == 0
          || (index == 1 && previousToken != null && "alternate".equalsIgnoreCase(previousToken));
    }

    private void appendToken(StringBuilder builder, String token) {
      if (builder.isEmpty()) {
        builder.append(token);
      } else {
        builder.append(' ').append(token);
      }
    }

    private String normalizeRevValue(String rev) {
      if (rev == null) {
        return "";
      }
      String lowercase = rev.toLowerCase();
      StringTokenizer tok = new StringTokenizer(lowercase, " ");
      StringBuilder builder = new StringBuilder(lowercase.length());
      while (tok.hasMoreTokens()) {
        String token = tok.nextToken();
        if (!isStandardLinkType(token)) {
          continue;
        }
        appendToken(builder, token);
      }
      return builder.toString();
    }

    private boolean handleStylesheetMetadata(
        Map<String, Object> attributes, Map<String, Object> output, LinkCharsetInfo info)
        throws DataFilterException {
      String media = getHashString(attributes, HtmlStrings.STR_MEDIA);
      if (media != null) {
        media = CSSReadFilter.filterMediaList(media);
        if (media != null) {
          output.put(HtmlStrings.STR_MEDIA, media);
        }
      }
      if (info.type != null && !info.type.startsWith(HtmlStrings.STR_TEXT_CSS)) {
        return false;
      }
      info.type = HtmlStrings.STR_TEXT_CSS;
      return true;
    }

    private void sanitizeHrefAttribute(
        Map<String, Object> attributes,
        Map<String, Object> output,
        LinkCharsetInfo charsetInfo,
        String fallbackCharset,
        boolean isIcon,
        String hreflang,
        HTMLParseContext pc)
        throws DataFilterException {
      String href = getHashString(attributes, "href");
      if (href == null) {
        return;
      }
      href = HTMLDecoder.decode(href);
      String sanitizedHref;
      if (isIcon) {
        sanitizedHref = htmlSanitizeURI(href, charsetInfo.type, null, null, pc.cb, pc, false);
      } else {
        sanitizedHref =
            htmlSanitizeURI(
                href, charsetInfo.type, charsetInfo.charset, fallbackCharset, pc.cb, pc, false);
      }
      if (sanitizedHref == null) {
        return;
      }
      sanitizedHref = HTMLEncoder.encode(sanitizedHref);
      output.put("href", sanitizedHref);
      if (charsetInfo.type != null) {
        output.put("type", charsetInfo.type);
      }
      if (charsetInfo.charset != null) {
        output.put(HtmlStrings.STR_CHARSET, charsetInfo.charset);
      }
      if (charsetInfo.charset != null && hreflang != null) {
        output.put(HtmlStrings.STR_HREFLANG, hreflang);
      }
    }

    private static final class LinkCharsetInfo {
      String type;
      String charset;
    }

    private record RelParseResult(
        String originalRel, String normalizedRel, boolean isStylesheet, boolean isIcon) {}

    // Does not include stylesheet
    private static final HashSet<String> standardRelTypes = new HashSet<>();

    static {
      // FIXME: more valid values from
      // https://www.iana.org/assignments/link-relations/link-relations.xhtml
      standardRelTypes.addAll(
          Arrays.asList(
              "alternate",
              "start",
              "next",
              "prev",
              "contents",
              "index",
              "glossary",
              "copyright",
              "chapter",
              HtmlStrings.STR_SECTION,
              "subsection",
              "appendix",
              "help",
              "bookmark"));
    }

    private boolean isStandardLinkType(String token) {
      return standardRelTypes.contains(token.toLowerCase());
    }
  }

  /**
   * Verify media tags (audio and video). This needs its own verifier, because different from
   * images, browsers use content sniffing to find out whether to display it as media content. Using
   * text/plain as content type would allow exploiting this to run unfiltered files as media files.
   * We fix this by encoding the mime type into the uri.
   */
  static class MediaTagVerifier extends CoreTagVerifier {
    private static final String[] locallyVerifiedAttrs = new String[] {"src"};

    MediaTagVerifier(
        String tag,
        String[] allowedAttrs,
        String[] uriAttrs,
        String[] inlineURIAttrs,
        String[] eventAttrs,
        String[] booleanAttrs) {
      super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, booleanAttrs);
      this.parsedAttrs.addAll(Arrays.asList(locallyVerifiedAttrs));
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);

      String src = getHashString(h, "src");
      if (src != null) {
        src = HTMLDecoder.decode(src);
        String type = ContentFilter.mimeTypeForSrc(src);
        src = htmlSanitizeURI(src, type, null, null, pc.cb, pc, false);
        if (src != null) {
          src = HTMLEncoder.encode(src);
          hn.put("src", src);
        }
      }
      return hn;
    }
  }

  // We do not allow forms to act anywhere else than on /
  static class FormTagVerifier extends CoreTagVerifier {
    private static final String[] locallyVerifiedAttrs =
        new String[] {HtmlStrings.STR_METHOD, HtmlStrings.STR_ACTION, "enctype", "accept-charset"};

    FormTagVerifier(String tag, String[] allowedAttrs, String[] uriAttrs, String[] eventAttrs) {
      super(tag, allowedAttrs, uriAttrs, null, eventAttrs, null);
      this.parsedAttrs.addAll(Arrays.asList(locallyVerifiedAttrs));
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      if (p.startSlash) {
        // Allow, but only with standard elements
        return hn;
      }
      String method = getHashString(h, HtmlStrings.STR_METHOD);
      String action = getHashString(h, HtmlStrings.STR_ACTION);
      String finalAction;
      try {
        finalAction = pc.cb.processForm(method, action);
      } catch (CommentException e) {
        pc.writeAfterTag
            .append(HtmlStrings.STR_COMMENT_PREFIX)
            .append(HTMLEncoder.encode(e.toString()))
            .append(" -->");
        return null;
      }
      if (finalAction == null) return null;
      hn.put(HtmlStrings.STR_METHOD, method);
      hn.put(HtmlStrings.STR_ACTION, finalAction);
      // Force enctype and accept-charset to acceptable values.
      hn.put("enctype", "multipart/form-data");
      hn.put("accept-charset", "UTF-8");
      return hn;
    }
  }

  static class InputTagVerifier extends CoreTagVerifier {
    private final HashSet<String> allowedTypes;

    InputTagVerifier(
        String tag,
        String[] allowedAttrs,
        String[] uriAttrs,
        String[] inlineURIAttrs,
        String[] eventAttrs) {
      super(tag, allowedAttrs, uriAttrs, inlineURIAttrs, eventAttrs, null);
      this.allowedTypes = new HashSet<>();
      // no ! file
      String[] types =
          new String[] {
            "text",
            "password",
            "checkbox",
            "radio",
            "submit",
            "reset",
            // no ! file
            "hidden",
            "image",
            HtmlStrings.STR_BUTTON,
            "email",
            "number",
            "search",
            "tel",
            "url"
          };
      if (types != null) {
        this.allowedTypes.addAll(Arrays.asList(types));
      }
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);

      // We drop the whole <input> if type isn't allowed (case-insensitive)
      if (hn.get("type") != null
          && !allowedTypes.contains(hn.get("type").toString().toLowerCase())) {
        return null;
      }

      return hn;
    }
  }

  static class MetaTagVerifier extends TagVerifier {
    private static final String[] allowedContentTypes = ContentFilter.HTML_MIME_TYPES;
    private static final String[] locallyVerifiedAttrs = {
      HtmlStrings.STR_HTTP_EQUIV, "name", HtmlStrings.STR_CONTENT, HtmlStrings.STR_CHARSET
    };

    private static final String[] validRobotsValue = {
      "all",
      "follow",
      "index",
      "noarchive",
      "nocache",
      "nofollow",
      "noimageindex",
      "noindex",
      "none",
      "nosnippet"
    };
    private static final HashSet<String> validRobotsValues;

    static {
      validRobotsValues = new HashSet<>();
      validRobotsValues.addAll(Arrays.asList(validRobotsValue));
    }

    MetaTagVerifier() {
      super("meta", new String[] {"id"});
      this.parsedAttrs.addAll(Arrays.asList(locallyVerifiedAttrs));
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      String httpEquiv = getHashString(h, HtmlStrings.STR_HTTP_EQUIV);
      String name = getHashString(h, "name");
      String content = getHashString(h, HtmlStrings.STR_CONTENT);
      String scheme = getHashString(h, "scheme");
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "meta: name={}, content={}, http-equiv={}, scheme={}",
            name,
            content,
            httpEquiv,
            scheme);
      }

      if (content != null) {
        if (hasNameOnly(name, httpEquiv)) {
          handleNamedMetaTag(name, content, hn);
        } else if (hasHttpEquivOnly(name, httpEquiv)) {
          if (!handleHttpEquivMeta(httpEquiv, content, hn, pc)) {
            return null;
          }
        }
      }

      handleCharsetDeclaration(h, hn, pc);
      return hn;
    }

    private boolean hasNameOnly(String name, String httpEquiv) {
      return name != null && httpEquiv == null;
    }

    private boolean hasHttpEquivOnly(String name, String httpEquiv) {
      return httpEquiv != null && name == null;
    }

    private void handleNamedMetaTag(String name, String content, Map<String, Object> output) {
      String lowered = name.toLowerCase();
      if (SUPPORTED_NAME_FIELDS.contains(lowered)) {
        output.put("name", name);
        output.put(HtmlStrings.STR_CONTENT, content);
        return;
      }
      if ("robots".equalsIgnoreCase(name) || "googlebot".equalsIgnoreCase(name)) {
        handleRobotsMeta(name, content, output);
      }
    }

    private void handleRobotsMeta(String name, String content, Map<String, Object> output) {
      StringBuilder normalized = new StringBuilder(content.length());
      for (String token : content.split(",")) {
        String trimmed = token.trim().toLowerCase();
        if (!validRobotsValues.contains(trimmed)) {
          continue;
        }
        if (!normalized.isEmpty()) {
          normalized.append(',').append(' ');
        }
        normalized.append(token.trim());
      }
      if (!normalized.isEmpty()) {
        output.put("name", name);
        output.put(HtmlStrings.STR_CONTENT, normalized.toString());
      }
    }

    private boolean handleHttpEquivMeta(
        String httpEquiv, String content, Map<String, Object> output, HTMLParseContext pc)
        throws DataFilterException {
      String lowered = httpEquiv.toLowerCase();
      switch (lowered) {
        case "expires":
          return handleExpiresMeta(content, output);
        case "content-script-type":
          return true;
        case "content-style-type":
          return handleStyleTypeMeta(content, output);
        case "content-type":
          return handleContentTypeMeta(httpEquiv, content, output, pc);
        case "content-language":
          return handleContentLanguageMeta(content, output);
        case HtmlStrings.STR_REFRESH:
          return handleRefreshMeta(content, output, pc);
        default:
          return true;
      }
    }

    private boolean handleExpiresMeta(String content, Map<String, Object> output) {
      try {
        ToadletContextImpl.parseHTTPDate(content);
        output.put(HtmlStrings.STR_HTTP_EQUIV, "Expires");
        output.put(HtmlStrings.STR_CONTENT, content);
        return true;
      } catch (ParseException e) {
        return false;
      }
    }

    private boolean handleStyleTypeMeta(String content, Map<String, Object> output) {
      if (content.equalsIgnoreCase(HtmlStrings.STR_TEXT_CSS)) {
        output.put(HtmlStrings.STR_HTTP_EQUIV, "Content-Style-Type");
        output.put(HtmlStrings.STR_CONTENT, content);
      }
      return true;
    }

    private boolean handleContentTypeMeta(
        String originalName, String content, Map<String, Object> output, HTMLParseContext pc)
        throws DataFilterException {
      if (LOG.isTraceEnabled()) {
        LOG.debug("Found http-equiv content-type={}", content);
      }
      String[] typesplit = splitType(content);
      for (String allowed : allowedContentTypes) {
        if (applyContentTypeIfAllowed(typesplit, allowed, originalName, output, pc)) {
          return true;
        }
      }
      throwFilterException(l10n("invalidMetaType"));
      return true;
    }

    private boolean applyContentTypeIfAllowed(
        String[] typesplit,
        String allowed,
        String originalName,
        Map<String, Object> output,
        HTMLParseContext pc)
        throws DataFilterException {
      if (!typesplit[0].equalsIgnoreCase(allowed)) {
        return false;
      }
      if (typesplit[1] == null || typesplit[1].equalsIgnoreCase(pc.charset)) {
        output.put(HtmlStrings.STR_HTTP_EQUIV, originalName);
        output.put(
            HtmlStrings.STR_CONTENT,
            typesplit[0] + (typesplit[1] != null ? "; charset=" + typesplit[1] : ""));
        return true;
      }
      if (pc.charset != null && !typesplit[1].equalsIgnoreCase(pc.charset)) {
        throwFilterException(l10n("wrongCharsetInMeta"));
      }
      if (typesplit[1] != null) {
        if (pc.detectedCharset != null) {
          throwFilterException(l10n(HtmlStrings.STR_MULTIPLE_CHARSETS_IN_META));
        }
        pc.detectedCharset = typesplit[1].trim();
      }
      return true;
    }

    private boolean handleContentLanguageMeta(String content, Map<String, Object> output) {
      if (content.matches("((?>[a-zA-Z0-9]*)(?>-[A-Za-z0-9]*)*(?>,\\s*)?)*")
          && !content.trim().isEmpty()) {
        output.put(HtmlStrings.STR_HTTP_EQUIV, "Content-Language");
        output.put(HtmlStrings.STR_CONTENT, content);
      }
      return true;
    }

    private boolean handleRefreshMeta(
        String content, Map<String, Object> output, HTMLParseContext pc)
        throws DataFilterException {
      int idx = content.indexOf(';');
      if (idx == -1 && metaRefreshSamePageMinInterval >= 0) {
        return handleSamePageRefresh(content, output, pc);
      }
      if (metaRefreshRedirectMinInterval >= 0) {
        return handleRedirectRefresh(content, idx, output, pc);
      }
      return true;
    }

    private boolean handleSamePageRefresh(
        String content, Map<String, Object> output, HTMLParseContext pc) {
      try {
        int seconds = Integer.parseInt(content);
        if (seconds < 0) {
          return false;
        }
        if (seconds < metaRefreshSamePageMinInterval) {
          seconds = metaRefreshSamePageMinInterval;
        }
        output.put(HtmlStrings.STR_HTTP_EQUIV, HtmlStrings.STR_REFRESH);
        output.put(HtmlStrings.STR_CONTENT, Integer.toString(seconds));
        return true;
      } catch (NumberFormatException e) {
        pc.writeAfterTag.append("<!-- doesn't parse as number in meta refresh -->");
        return false;
      }
    }

    private boolean handleRedirectRefresh(
        String content, int separatorIndex, Map<String, Object> output, HTMLParseContext pc)
        throws DataFilterException {
      try {
        int seconds = Integer.parseInt(content.substring(0, separatorIndex));
        if (seconds < 0) {
          return false;
        }
        if (seconds < metaRefreshRedirectMinInterval) {
          seconds = metaRefreshRedirectMinInterval;
        }
        String after = content.substring(separatorIndex + 1).trim();
        if (!after.toLowerCase().startsWith("url=")) {
          pc.writeAfterTag.append("<!-- no url but doesn't parse as number in meta refresh -->");
          return false;
        }
        after = after.substring("url=".length()).trim();
        try {
          String url = sanitizeURI(after, null, null, null, pc.cb, false);
          output.put(HtmlStrings.STR_HTTP_EQUIV, HtmlStrings.STR_REFRESH);
          output.put(HtmlStrings.STR_CONTENT, seconds + "; url=" + HTMLEncoder.encode(url));
          return true;
        } catch (CommentException e) {
          pc.writeAfterTag
              .append(HtmlStrings.STR_COMMENT_PREFIX)
              .append(e.getMessage())
              .append("-->");
          return false;
        }
      } catch (NumberFormatException e) {
        pc.writeAfterTag.append(
            "<!-- doesn't parse as number in meta refresh possibly with url -->");
        return false;
      }
    }

    private void handleCharsetDeclaration(
        Map<String, Object> attributes, Map<String, Object> output, HTMLParseContext pc)
        throws DataFilterException {
      String charset = getHashString(attributes, HtmlStrings.STR_CHARSET);
      if (charset == null) {
        return;
      }
      if (pc.detectedCharset != null && !charset.equalsIgnoreCase(pc.detectedCharset)) {
        throwFilterException(l10n(HtmlStrings.STR_MULTIPLE_CHARSETS_IN_META));
      }
      pc.detectedCharset = charset;
      output.put(HtmlStrings.STR_CHARSET, charset);
    }

    private static final Set<String> SUPPORTED_NAME_FIELDS =
        new HashSet<>(Arrays.asList("author", "keywords", "description", "viewport"));

    @Override
    protected boolean expungeTagIfNoAttributes() {
      return true;
    }
  }

  static class DocTypeTagVerifier extends TagVerifier {
    DocTypeTagVerifier(String tag) {
      super(tag, null);
    }

    private static final Map<String, Object> DTDs = new HashMap<>();

    static {
      DTDs.put(
          "-//W3C//DTD XHTML 1.0 Strict//EN", "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd");
      DTDs.put(
          "-//W3C//DTD XHTML 1.0 Transitional//EN",
          "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd");
      DTDs.put(
          "-//W3C//DTD XHTML 1.0 Frameset//EN",
          "http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd");
      DTDs.put("-//W3C//DTD XHTML 1.1//EN", "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd");
      DTDs.put("-//W3C//DTD HTML 4.01//EN", "http://www.w3.org/TR/html4/strict.dtd");
      DTDs.put("-//W3C//DTD HTML 4.01 Transitional//EN", "http://www.w3.org/TR/html4/loose.dtd");
      DTDs.put("-//W3C//DTD HTML 4.01 Frameset//EN", "http://www.w3.org/TR/html4/frameset.dtd");
      DTDs.put("-//W3C//DTD HTML 3.2 Final//EN", new Object());
    }

    @Override
    ParsedTag sanitize(ParsedTag t, HTMLParseContext pc) {
      if (isSimpleHtml5Doctype(t)) {
        return t;
      }
      if (!hasSupportedAttributeCount(t) || !startsWithHtml(t)) {
        return null;
      }
      if (isLegacySystemDoctype(t)) {
        return handleLegacySystemDoctype(t);
      }
      if (!isPublicDoctype(t) || !isKnownPublicIdentifier(t)) {
        return null;
      }
      if (t.unparsedAttrs.length == 4 && !matchesExpectedSystemIdentifier(t)) {
        return null;
      }
      return t;
    }

    private boolean isSimpleHtml5Doctype(ParsedTag tag) {
      return tag.unparsedAttrs.length == 1 && tag.unparsedAttrs[0].equalsIgnoreCase("html");
    }

    private boolean hasSupportedAttributeCount(ParsedTag tag) {
      return tag.unparsedAttrs.length == 3 || tag.unparsedAttrs.length == 4;
    }

    private boolean startsWithHtml(ParsedTag tag) {
      return tag.unparsedAttrs[0].equalsIgnoreCase("html");
    }

    private boolean isLegacySystemDoctype(ParsedTag tag) {
      return tag.unparsedAttrs[1].equalsIgnoreCase("system") && tag.unparsedAttrs.length == 3;
    }

    private ParsedTag handleLegacySystemDoctype(ParsedTag tag) {
      String value = stripQuotes(tag.unparsedAttrs[2]);
      return value.equals("about:legacy-compat") ? tag : null;
    }

    private boolean isPublicDoctype(ParsedTag tag) {
      return tag.unparsedAttrs[1].equalsIgnoreCase("public");
    }

    private boolean isKnownPublicIdentifier(ParsedTag tag) {
      String identifier = stripQuotes(tag.unparsedAttrs[2]);
      return DTDs.containsKey(identifier);
    }

    private boolean matchesExpectedSystemIdentifier(ParsedTag tag) {
      String identifier = stripQuotes(tag.unparsedAttrs[2]);
      String expected = getHashString(DTDs, identifier);
      String actual = stripQuotes(tag.unparsedAttrs[3]);
      return expected == null || expected.equals(actual);
    }
  }

  static class XmlTagVerifier extends TagVerifier {
    XmlTagVerifier() {
      super("?xml", null);
    }

    @Override
    ParsedTag sanitize(ParsedTag t, HTMLParseContext pc) throws DataFilterException {
      if (!hasValidAttributeLength(t)) {
        logXmlDebug("Deleting xml declaration, invalid length");
        return null;
      }
      if (!hasValidEndingToken(t)) {
        return null;
      }
      if (!hasValidVersionToken(t)) {
        logXmlDebug("Deleting xml declaration, invalid version");
        return null;
      }
      String charset = extractCharset(t);
      if (charset == null) {
        logXmlDebug(HtmlStrings.STR_DELETING_XML_DECLARATION_INVALID_ENCODING);
        return null;
      }
      if (!charset.equalsIgnoreCase(pc.charset)) {
        if (pc.charset != null) {
          logXmlDebug(
              "Deleting xml declaration (invalid charset "
                  + charset
                  + " should be "
                  + pc.charset
                  + ")");
          return null;
        }
        if (pc.detectedCharset != null) {
          throwFilterException(l10n(HtmlStrings.STR_MULTIPLE_CHARSETS_IN_META));
        }
        pc.detectedCharset = charset;
      }
      return t;
    }

    private boolean hasValidAttributeLength(ParsedTag tag) {
      return tag.unparsedAttrs.length == 2 || tag.unparsedAttrs.length == 3;
    }

    private boolean hasValidEndingToken(ParsedTag tag) {
      if (tag.unparsedAttrs.length == 3 && !"?".equals(tag.unparsedAttrs[2])) {
        logXmlDebug("Deleting xml declaration, invalid ending (length 2)");
        return false;
      }
      if (tag.unparsedAttrs.length == 2 && !tag.unparsedAttrs[1].endsWith("?")) {
        logXmlDebug("Deleting xml declaration, invalid ending (length 3)");
        return false;
      }
      return true;
    }

    private boolean hasValidVersionToken(ParsedTag tag) {
      return "version=\"1.0\"".equals(tag.unparsedAttrs[0])
          || "version='1.0'".equals(tag.unparsedAttrs[0]);
    }

    private String extractCharset(ParsedTag tag) {
      String encodingAttr = tag.unparsedAttrs[1];
      if (encodingAttr.startsWith("encoding=\"")) {
        if (!encodingAttr.endsWith("\"")) {
          return null;
        }
        return encodingAttr.substring("encoding=\"".length(), encodingAttr.length() - 1);
      }
      if (encodingAttr.startsWith("encoding='")) {
        if (!encodingAttr.endsWith("'")) {
          return null;
        }
        return encodingAttr.substring("encoding='".length(), encodingAttr.length() - 1);
      }
      return null;
    }

    private void logXmlDebug(String message) {
      if (LOG.isDebugEnabled()) {
        LOG.debug(message);
      }
    }
  }

  static class HtmlTagVerifier extends TagVerifier {
    private static final String[] locallyVerifiedAttrs = new String[] {HtmlStrings.STR_XMLNS};

    HtmlTagVerifier() {
      super("html", new String[] {"id", "version"});
      this.parsedAttrs.addAll(Arrays.asList(locallyVerifiedAttrs));
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      String xmlns = getHashString(h, HtmlStrings.STR_XMLNS);
      if ((xmlns != null) && xmlns.equals("http://www.w3.org/1999/xhtml")) {
        hn.put(HtmlStrings.STR_XMLNS, xmlns);
        pc.setisXHTML(true);
      }
      return hn;
    }
  }

  static class BaseHrefTagVerifier extends TagVerifier {
    private static final String[] locallyVerifiedAttrs = new String[] {"href"};

    BaseHrefTagVerifier(String tag, String[] allowedAttrs, String[] uriAttrs) {
      super(tag, allowedAttrs, uriAttrs, null, emptyStringArray);
      this.parsedAttrs.addAll(Arrays.asList(locallyVerifiedAttrs));
    }

    @Override
    Map<String, Object> sanitizeHash(Map<String, Object> h, ParsedTag p, HTMLParseContext pc)
        throws DataFilterException {
      Map<String, Object> hn = super.sanitizeHash(h, p, pc);
      String baseHref = getHashString(h, "href");
      if (baseHref != null) {
        // Decode and encode for the same reason we do in sanitizeHash().
        baseHref = HTMLDecoder.decode(baseHref);
        String ref = pc.cb.onBaseHref(baseHref);
        if (ref != null) {
          hn.put("href", HTMLEncoder.encode(ref));
          return hn;
        }
      }
      pc.writeAfterTag.append("<!-- deleted invalid base href -->");
      return null;
    }
  }

  static String sanitizeStyle(
      String style, FilterCallback cb, HTMLParseContext hpc, boolean isInline)
      throws DataFilterException {
    if (style == null) return null;
    if (hpc.onlyDetectingCharset) return null;
    Reader r = new StringReader(style);
    Writer w = new StringWriter();
    style = style.trim();
    if (LOG.isDebugEnabled()) LOG.debug("Sanitizing style: " + style);
    CSSParser pc = new CSSParser(r, w, false, cb, hpc.charset, false, isInline);
    try {
      pc.parse();
    } catch (IOException e) {
      LOG.error("IOException parsing inline CSS!");
    } catch (Error e) {
      if (e.getMessage().equals("Error: could not match input")) {
        // this sucks, it should be a proper exception
        LOG.info("CSS Parse Error!", e);
        return "/* " + l10n("couldNotParseStyle") + " */";
      } else throw e;
    }
    String s = w.toString();
    if ((s == null) || s.isEmpty()) return null;
    //		Core.logger.log(SaferFilter.class, "Style now: " + s, LogLevel.DEBUG);
    if (LOG.isDebugEnabled()) LOG.debug("Style finally: " + s);
    return s;
  }

  static String escapeQuotes(String s) {
    StringBuilder buf = new StringBuilder(s.length());
    for (int x = 0; x < s.length(); x++) {
      char c = s.charAt(x);
      if (c == '\"') {
        buf.append("&quot;");
      } else {
        buf.append(c);
      }
    }
    return buf.toString();
  }

  static String sanitizeScripting(String script) {
    // Kill it. At some point we may want to allow certain recipes - FIXME
    return null;
  }

  static String sanitizeURI(String uri, FilterCallback cb, boolean inline) throws CommentException {
    return sanitizeURI(uri, null, null, null, cb, inline);
  }

  /*
   * While we're only interested in the type and the charset, the format is a
   * lot more flexible than that. (avian) TEXT/PLAIN; format=flowed;
   * charset=US-ASCII IMAGE/JPEG; name=test.jpeg; x-unix-mode=0644
   */
  public static String[] splitType(String type) {
    StringFieldParser sfp;
    String charset = null, param, name, value;
    int x;

    sfp = new StringFieldParser(type, ';');
    type = sfp.nextField().trim();
    while (sfp.hasMoreFields()) {
      param = sfp.nextField();
      x = param.indexOf('=');
      if (x != -1) {
        name = param.substring(0, x).trim();
        value = param.substring(x + 1).trim();
        if (name.equals(HtmlStrings.STR_CHARSET)) charset = value;
      }
    }
    return new String[] {type, charset};
  }

  // A simple string splitter
  // StringTokenizer doesn't work well for our purpose. (avian)
  static class StringFieldParser {
    private final String str;
    private final int maxPos;
    private int curPos;
    private final char c;

    public StringFieldParser(String str) {
      this(str, '\t');
    }

    public StringFieldParser(String str, char c) {
      this.str = str;
      this.maxPos = str.length();
      this.curPos = 0;
      this.c = c;
    }

    public boolean hasMoreFields() {
      return curPos <= maxPos;
    }

    public String nextField() {
      int start, end;

      if (curPos > maxPos) return null;
      start = curPos;
      while ((curPos < maxPos) && (str.charAt(curPos) != c)) curPos++;
      end = curPos;
      curPos++;
      return str.substring(start, end);
    }
  }

  static String htmlSanitizeURI(
      String suri,
      String overrideType,
      String overrideCharset,
      String maybeCharset,
      FilterCallback cb,
      HTMLParseContext pc,
      boolean inline) {
    try {
      return sanitizeURI(suri, overrideType, overrideCharset, maybeCharset, cb, inline);
    } catch (CommentException e) {
      pc.writeAfterTag
          .append(HtmlStrings.STR_COMMENT_PREFIX)
          .append(HTMLEncoder.encode(e.toString()))
          .append(" -->");
      return null;
    }
  }

  static String sanitizeURI(
      String suri,
      String overrideType,
      String overrideCharset,
      String maybeCharset,
      FilterCallback cb,
      boolean inline)
      throws CommentException {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Sanitizing URI: "
              + suri
              + " ( override type "
              + overrideType
              + " override charset "
              + overrideCharset
              + " ) inline="
              + inline,
          new Exception("debug"));
    boolean addMaybe = false;
    if ((overrideCharset != null) && !overrideCharset.isEmpty())
      overrideType += "; charset=" + overrideCharset;
    else if (maybeCharset != null) addMaybe = true;
    String retval = cb.processURI(suri, overrideType, false, inline);
    if (addMaybe) {
      if (retval.indexOf('?') != -1) retval += "&maybecharset=" + maybeCharset;
      else retval += "?maybecharset=" + maybeCharset;
    }
    return retval;
  }

  static String getHashString(Map<String, Object> h, String key) {
    Object o = h.get(key);
    if (o == null) return null;
    if (o instanceof String string) return string;
    else return null;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("HTMLFilter." + key);
  }

  private static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("HTMLFilter." + key, pattern, value);
  }

  @Override
  public BOMDetection getCharsetByBOM(byte[] input, int length) throws DataFilterException {
    // No enhanced BOMs.
    // FIXME XML BOMs???
    return null;
  }

  @Override
  public int getCharsetBufferSize() {
    // Read in 64 kilobytes. The charset could be defined anywhere in the head section
    return 1024 * 64;
  }
}
