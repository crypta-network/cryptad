package network.crypta.clients.http;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.font.FontRenderContext;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import javax.imageio.ImageIO;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;

/**
 * Generates PNG images that render caller-provided text for lightweight previews and diagnostics.
 *
 * <p>This toadlet is a small utility endpoint used by the HTTP UI to quickly turn arbitrary text
 * into a black-on-white raster image. Callers pass the desired content via the {@code text}
 * parameter and may optionally influence the canvas size through {@code width} and {@code height}
 * query parameters. When either dimension is omitted, sensible defaults keep the output compact
 * enough for inline display. Oversized inputs are rejected to avoid unbounded memory growth and to
 * keep latency predictable even under a concurrent load.
 *
 * <p>Responses include a strong {@code Last-Modified} header keyed to the class timestamp so
 * browsers can reuse cached images without regenerating them on every request. The implementation
 * is effectively stateless; each request builds its own buffer and disposes of it immediately after
 * the PNG is streamed to the client-side bucket. No shared mutable state is retained, so instances
 * are safe to serve multiple requests concurrently when registered with the toadlet server.
 *
 * <ul>
 *   <li>Creates centered text with automatic font sizing to fit the requested rectangle.
 *   <li>Rejects dimensions larger than a configurable upper bound to cap resource use.
 *   <li>Returns {@code 304 Not Modified} when the client already holds the current image.
 * </ul>
 *
 * @see network.crypta.clients.http.Toadlet
 */
public class ImageCreatorToadlet extends ContentToadlet {

  private static final String ROOT_URL = "/imagecreator/";

  /**
   * Default image width in pixels when callers omit the {@code width} query parameter.
   *
   * <p>The value is small enough for inline previews yet large enough to render short labels
   * legibly on typical UI elements. Requests may override it with any positive number up to the
   * maximum enforced by {@link #validateDimensions(int, int, ToadletContext)}.
   */
  public static final int DEFAULT_WIDTH = 100;

  /**
   * Default image height in pixels when callers omit the {@code height} query parameter.
   *
   * <p>Combined with {@link #DEFAULT_WIDTH}, this size produces a square canvas suitable for icons
   * and quick previews. Larger heights are permitted within the hard limit checked during request
   * validation.
   */
  public static final int DEFAULT_HEIGHT = 100;

  private static final short WIDTH_AND_HEIGHT_LIMIT = 3500;

  /**
   * Timestamp used for {@code Last-Modified} caching headers to prevent redundant image rendering.
   *
   * <p>Update this value whenever the rendering behavior or resource output changes so browsers can
   * correctly invalidate cached responses and fetch a fresh image.
   */
  protected static final Instant LAST_MODIFIED = Instant.ofEpochMilli(1593361729000L);

  private static final String WIDTH_PARAM = "width";
  private static final String HEIGHT_PARAM = "height";

  /**
   * Builds a new image creator toadlet bound to the provided high-level client utilities.
   *
   * <p>The supplied {@link BrowseContentClient} must remain valid for the lifetime of this toadlet
   * because it underpins the inherited {@link Toadlet} behaviors such as bucket allocation and
   * response writing. Instances created through this constructor are stateless; multiple toadlets
   * may coexist and serve concurrent requests as long as the client manages shared resources
   * safely. Callers typically register the instance with the toadlet server immediately after
   * construction, so HTTP requests under the configured path are dispatched here.
   *
   * @param client non-null browse-side content client used for bucket creation and other inherited
   *     helpers
   */
  protected ImageCreatorToadlet(BrowseContentClient client) {
    super(client);
  }

  /**
   * Handles HTTP {@code GET} requests by generating or reusing a cached PNG that contains the
   * supplied text.
   *
   * <p>The method first evaluates {@code If-Modified-Since} to send a {@code 304 Not Modified}
   * response when the client already holds the latest image. It then parses {@code width} and
   * {@code height} query parameters, applying defaults and rejecting non-positive or oversized
   * values. Upon success, it renders white text centered on a black background, choosing the
   * largest font that fits the requested rectangle. Output is streamed to a bucket and returned
   * with {@code image/png} content type and caching headers.
   *
   * @param uri request URI pointing at this toadlet; the path is ignored beyond routing
   * @param req HTTP request carrying the {@code text}, {@code width}, and {@code height} parameters
   * @param ctx toadlet context providing bucket factories, headers, and reply helpers; never null
   * @throws ToadletContextClosedException if the connection closes before the reply is fully sent
   * @throws IOException if writing image data to the bucket or client output stream fails
   * @throws RedirectException if upstream logic requests redirect handling for this request
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (clientHasCurrentImage(ctx)) {
      return;
    }

    String text = req.getParam("text");
    int requiredWidth = parseDimension(req.getParam(WIDTH_PARAM), DEFAULT_WIDTH);
    int requiredHeight = parseDimension(req.getParam(HEIGHT_PARAM), DEFAULT_HEIGHT);

    if (!validateDimensions(requiredWidth, requiredHeight, ctx)) {
      return;
    }

    BufferedImage buffer =
        new BufferedImage(requiredWidth, requiredHeight, BufferedImage.TYPE_INT_RGB);
    Graphics2D g2 = buffer.createGraphics();
    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
    FontRenderContext fc = g2.getFontRenderContext();
    specifyMaximumFontSizeThatFitsInImage(g2, fc, requiredWidth, requiredHeight, text);
    Rectangle2D bounds = g2.getFont().getStringBounds(text, fc);
    g2.setColor(new Color(0, 0, 0));
    g2.fillRect(0, 0, requiredWidth, requiredHeight);
    g2.setColor(new Color(255, 255, 255));
    g2.drawString(
        text,
        (int) ((double) requiredWidth / 2 - bounds.getWidth() / 2),
        (int) ((double) requiredHeight / 2 + bounds.getHeight() / 4));

    Bucket data = ctx.getBucketFactory().makeBucket(-1);
    try (OutputStream os = data.getOutputStream()) {
      ImageIO.write(buffer, "png", os);
    }
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    ctx.sendReplyHeadersStatic(200, "OK", headers, "image/png", data.size(), LAST_MODIFIED);
    ctx.writeData(data);
  }

  /**
   * Returns the absolute path segment under which this toadlet is exposed to HTTP callers.
   *
   * <p>The path is constant ({@value #ROOT_URL}) and should be used when registering the toadlet
   * with the container and when clients build request URLs. The returned value includes trailing
   * slashes as expected by the surrounding routing infrastructure and is safe to reuse across
   * threads because it references an immutable constant.
   *
   * @return immutable string representing the URL prefix {@code /imagecreator/} used for routing
   */
  @Override
  public String path() {
    return ROOT_URL;
  }

  void specifyMaximumFontSizeThatFitsInImage(
      Graphics2D g2, FontRenderContext fc, int imageWidth, int imageHeight, String text) {
    int minFontSize = 1;
    int maxFontSize = Math.max(imageWidth, imageHeight);
    int betweenFontSize = betweenFontSize(minFontSize, maxFontSize);
    g2.setFont(g2.getFont().deriveFont((float) betweenFontSize));
    while (maxFontSize > minFontSize) {
      Rectangle2D bounds = g2.getFont().getStringBounds(text, fc);
      if (bounds.getWidth() > imageWidth || bounds.getHeight() > imageHeight) {
        maxFontSize = betweenFontSize - 1;
      } else {
        minFontSize = betweenFontSize;
      }
      betweenFontSize = betweenFontSize(minFontSize, maxFontSize);
      g2.setFont(g2.getFont().deriveFont((float) betweenFontSize));
    }
  }

  private int betweenFontSize(int from, int to) {
    int between = from + (to - from) / 2;
    if (between == from) {
      return to; // depends on specifyMaximumFontSizeThatFitsInImage
    }
    return between;
  }

  private boolean clientHasCurrentImage(ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (ctx.getHeaders().containsKey("if-modified-since")) {
      try {
        Instant ifModifiedSince =
            ToadletContextImpl.parseHTTPDate(ctx.getHeaders().getFirst("if-modified-since"));
        if (ifModifiedSince.equals(LAST_MODIFIED)) {
          ctx.sendReplyHeadersStatic(304, "Not Modified", null, "image/png", 0, LAST_MODIFIED);
          return true;
        }
      } catch (ParseException _) {
        return false;
      }
    }
    return false;
  }

  private int parseDimension(String rawValue, int defaultValue) {
    if (rawValue == null || rawValue.isEmpty()) {
      return defaultValue;
    }
    String numeric =
        rawValue.endsWith("px") ? rawValue.substring(0, rawValue.length() - 2) : rawValue;
    return Integer.parseInt(numeric);
  }

  private boolean validateDimensions(int requiredWidth, int requiredHeight, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (requiredWidth <= 0 || requiredHeight <= 0) {
      writeHTMLReply(ctx, 400, "Bad request", "Illegal argument");
      return false;
    }
    if (requiredWidth > WIDTH_AND_HEIGHT_LIMIT || requiredHeight > WIDTH_AND_HEIGHT_LIMIT) {
      writeHTMLReply(
          ctx,
          400,
          "Bad request",
          "Too large (max " + WIDTH_AND_HEIGHT_LIMIT + "x" + WIDTH_AND_HEIGHT_LIMIT + "px)");
      return false;
    }
    return true;
  }
}
