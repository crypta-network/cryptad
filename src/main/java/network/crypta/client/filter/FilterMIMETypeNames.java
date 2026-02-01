package network.crypta.client.filter;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Identifies a MIME type and its common filename extensions.
 *
 * <p>This value object bundles the canonical type string with any alternate type aliases and
 * filename extensions so callers can pass a single immutable object when registering handlers.
 */
public final class FilterMIMETypeNames {
  private final String primaryMimeType;
  private final String primaryExtension;
  private final String[] alternateMimeTypes;
  private final String[] alternateExtensions;

  /**
   * Creates a MIME type descriptor with optional aliases and extensions.
   *
   * @param primaryMimeType canonical MIME type name (for example, {@code "text/html"})
   * @param primaryExtension primary filename extension without the leading dot (for example, {@code
   *     "html"})
   * @param alternateMimeTypes additional MIME type aliases accepted for this handler
   * @param alternateExtensions additional filename extensions associated with the type
   */
  public FilterMIMETypeNames(
      String primaryMimeType,
      String primaryExtension,
      String[] alternateMimeTypes,
      String[] alternateExtensions) {
    this.primaryMimeType = primaryMimeType;
    this.primaryExtension = primaryExtension;
    this.alternateMimeTypes = alternateMimeTypes;
    this.alternateExtensions = alternateExtensions;
  }

  public String primaryMimeType() {
    return primaryMimeType;
  }

  public String primaryExtension() {
    return primaryExtension;
  }

  public String[] alternateMimeTypes() {
    return alternateMimeTypes;
  }

  public String[] alternateExtensions() {
    return alternateExtensions;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof FilterMIMETypeNames other)) {
      return false;
    }
    return Objects.equals(primaryMimeType, other.primaryMimeType)
        && Objects.equals(primaryExtension, other.primaryExtension)
        && Arrays.equals(alternateMimeTypes, other.alternateMimeTypes)
        && Arrays.equals(alternateExtensions, other.alternateExtensions);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(primaryMimeType, primaryExtension);
    result = 31 * result + Arrays.hashCode(alternateMimeTypes);
    result = 31 * result + Arrays.hashCode(alternateExtensions);
    return result;
  }

  @Override
  public @NotNull String toString() {
    return "FilterMIMETypeNames["
        + "primaryMimeType="
        + primaryMimeType
        + ", primaryExtension="
        + primaryExtension
        + ", alternateMimeTypes="
        + formatArray(alternateMimeTypes)
        + ", alternateExtensions="
        + formatArray(alternateExtensions)
        + "]";
  }

  private static String formatArray(String[] values) {
    return values == null ? "null" : Arrays.toString(values);
  }
}
