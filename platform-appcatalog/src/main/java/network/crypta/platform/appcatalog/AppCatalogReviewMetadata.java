package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.Optional;

/**
 * Advisory human-review metadata for one catalog app.
 *
 * <p>Catalog publishers can use this value to describe the human review state they want operators
 * to see before an installation or update. The metadata is authenticated as part of the signed
 * catalog, so an operator can tell which trusted catalog source made the claim. It is still only
 * advisory. It does not turn a catalog into a code-signing authority, bypass artifact digest
 * checks, replace signed-bundle verification, grant app permissions, or block install/update on its
 * own.
 *
 * <p>The status is intentionally small and enumerable so Platform API and Web Shell clients can
 * render consistent badges. The optional note gives the publisher one concise line of context, such
 * as what was reviewed or why the operator should use caution. Longer review reports should use
 * catalog documentation or a changelog URI rather than this field.
 *
 * <p>Instances are immutable and validate the note at construction time. The note is trimmed,
 * bounded, and single-line, which keeps the deterministic catalog sidecar format readable and
 * prevents metadata from introducing extra properties through embedded line breaks.
 *
 * @param status advisory review status declared by the catalog publisher
 * @param note optional single-line review note shown to operators
 * @see AppCatalogReviewStatus
 * @see AppCatalogEntry#review()
 */
public record AppCatalogReviewMetadata(AppCatalogReviewStatus status, Optional<String> note) {
  private static final int MAX_REVIEW_NOTE_CHARS = 512;

  /**
   * Empty advisory review metadata used by catalogs without explicit review fields.
   *
   * <p>This value maps to {@link AppCatalogReviewStatus#UNREVIEWED} with no note. Writers omit
   * review properties for it, while API responses can still expose a stable review object.
   */
  public static final AppCatalogReviewMetadata EMPTY =
      new AppCatalogReviewMetadata(AppCatalogReviewStatus.UNREVIEWED, Optional.empty());

  /**
   * Creates validated review metadata.
   *
   * <p>The constructor does not interpret the review as trust. It only ensures the value is safe to
   * store in a signed catalog sidecar and expose through Platform API JSON. A blank present note is
   * rejected because callers should use {@link Optional#empty()} when no note exists.
   *
   * @param status advisory review status declared by the catalog publisher
   * @param note optional single-line note explaining the status for operators
   * @throws NullPointerException if the status or optional wrapper is {@code null}
   * @throws AppCatalogException if the note is blank, multi-line, or too long
   */
  public AppCatalogReviewMetadata {
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(note, "note");
    note =
        note.map(
            rawNote ->
                AppCatalogSidecars.requireBoundedSingleLine(
                    rawNote,
                    "review.note",
                    AppCatalogSidecars.INVALID_CATALOG_ENTRY,
                    MAX_REVIEW_NOTE_CHARS));
  }

  /**
   * Returns whether this value should be written to a catalog sidecar.
   *
   * <p>The minimal catalog format stays compact by omitting default review metadata. A non-default
   * status or any present note is meaningful catalog data and should be serialized so the signed
   * sidecar carries the publisher's advisory review state.
   *
   * @return {@code true} when a non-default status or a note is present
   */
  public boolean hasCatalogFields() {
    return status != AppCatalogReviewStatus.UNREVIEWED || note.isPresent();
  }
}
