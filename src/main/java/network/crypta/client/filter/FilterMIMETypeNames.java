package network.crypta.client.filter;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Identifies a MIME type and its common filename extensions.
 *
 * <p>This record bundles the canonical type string with any alternate type aliases and filename
 * extensions so callers can pass a single immutable object when registering handlers.
 *
 * @param primaryMimeType canonical MIME type name (for example, {@code "text/html"})
 * @param primaryExtension primary filename extension without the leading dot (for example, {@code
 *     "html"})
 * @param alternateMimeTypes additional MIME type aliases accepted for this handler
 * @param alternateExtensions additional filename extensions associated with the type
 */
@SuppressWarnings("ArrayRecordComponent")
public record FilterMIMETypeNames(
    String primaryMimeType,
    String primaryExtension,
    String[] alternateMimeTypes,
    String[] alternateExtensions) {

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj
        instanceof
        FilterMIMETypeNames(
            String otherPrimaryMimeType,
            String otherPrimaryExtension,
            String[] otherAlternateMimeTypes,
            String[] otherAlternateExtensions))) {
      return false;
    }
    return Objects.equals(primaryMimeType, otherPrimaryMimeType)
        && Objects.equals(primaryExtension, otherPrimaryExtension)
        && Arrays.equals(alternateMimeTypes, otherAlternateMimeTypes)
        && Arrays.equals(alternateExtensions, otherAlternateExtensions);
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
