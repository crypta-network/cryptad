package network.crypta.platform.appcatalog;

import java.util.Objects;
import java.util.Optional;

/**
 * Operator-facing rollback candidate for a retained verified catalog revision.
 *
 * <p>Eligibility is evaluated against current trusted catalog keys before the candidate is exposed
 * or executed. A candidate can be visible but ineligible, for example when its signing key has
 * since been revoked or removed from local trust configuration.
 */
public record AppCatalogRollbackCandidate(
    AppCatalogVerifiedRevision revision, boolean eligible, Optional<String> reason) {
  /** Creates validated rollback metadata. */
  public AppCatalogRollbackCandidate {
    Objects.requireNonNull(revision, "revision");
    Objects.requireNonNull(reason, "reason");
  }
}
