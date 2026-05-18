package network.crypta.platform.trustgraph;

/**
 * Subject/context query for local Trust Graph Preview scoring.
 *
 * <p>The query shape mirrors the score route parameters. Matching is exact: subject kind, subject
 * URI, and context must all match a retained statement payload before the scorer considers that
 * statement as evidence. This keeps preview scoring deterministic and avoids fuzzy identity or URI
 * normalization rules.
 *
 * @param subjectKind bounded subject kind selected by the caller
 * @param subjectUri bounded subject URI or stable subject string
 * @param context trust context such as {@code profile} or {@code app-review}
 */
public record TrustGraphQuery(TrustSubjectKind subjectKind, String subjectUri, String context) {
  /** Creates a normalized query. */
  public TrustGraphQuery {
    java.util.Objects.requireNonNull(subjectKind, "subjectKind");
    subjectUri = TrustStatementValidator.requiredText("subjectUri", subjectUri, 1024);
    context = TrustStatementValidator.requiredContext(context);
  }

  /**
   * Returns whether a payload belongs to this query's subject and context.
   *
   * @param payload validated statement payload to compare with this query
   * @return {@code true} when subject kind, subject URI, and context all match exactly
   */
  public boolean matches(TrustStatementPayload payload) {
    return payload.subject().kind() == subjectKind
        && payload.subject().uri().equals(subjectUri)
        && payload.context().equals(context);
  }
}
