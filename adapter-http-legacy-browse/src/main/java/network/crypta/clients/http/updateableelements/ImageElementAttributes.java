package network.crypta.clients.http.updateableelements;

/**
 * Size and accessibility attributes for an image element.
 *
 * @param width the width attribute in CSS pixels, or {@code -1} to omit it
 * @param height the height attribute in CSS pixels, or {@code -1} to omit it
 * @param name optional accessible name used for {@code alt} and {@code title}
 */
public record ImageElementAttributes(int width, int height, String name) {
  public static ImageElementAttributes unspecified() {
    return new ImageElementAttributes(-1, -1, null);
  }
}
