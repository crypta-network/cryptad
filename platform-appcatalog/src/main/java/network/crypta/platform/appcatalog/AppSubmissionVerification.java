package network.crypta.platform.appcatalog;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Result of structurally verifying a submission package.
 *
 * <p>This record is the non-throwing inspection result returned by {@link
 * AppSubmissionPackageVerifier#inspect(java.nio.file.Path)}. It is designed for CLI and
 * release-certification flows that need to report malformed or unsafe submissions as deterministic
 * JSON instead of aborting with raw exceptions. A parsed package snapshot is present only when the
 * metadata, manifest, and required artifact bytes could be read safely.
 *
 * <p>The invariant is strict: if {@code submission} is {@code null}, at least one blocker finding
 * must explain why parsing stopped. That keeps callers from treating an unparsed package as a
 * warning-only result.
 *
 * @param submission parsed package snapshot, or {@code null} when parsing was blocked by redacted
 *     findings
 * @param findings redacted structural and redaction findings in deterministic order
 */
public record AppSubmissionVerification(
    AppSubmissionPackage submission, List<AppSubmissionFinding> findings) {
  /**
   * Creates a verification result.
   *
   * <p>The finding list is defensively copied. A missing package snapshot is allowed only when a
   * blocker finding is present, which matches the verifier's fail-closed reporting contract.
   */
  public AppSubmissionVerification {
    findings = List.copyOf(Objects.requireNonNull(findings, "findings"));
    if (submission == null && findings.stream().noneMatch(AppSubmissionFinding::blocksPromotion)) {
      throw new NullPointerException("submission");
    }
  }

  /**
   * Returns whether any blocker findings were produced.
   *
   * @return {@code true} when at least one finding blocks promotion
   */
  public boolean hasBlockers() {
    return findings.stream().anyMatch(AppSubmissionFinding::blocksPromotion);
  }

  /**
   * Returns whether the package metadata and manifest were parsed successfully.
   *
   * @return {@code true} when {@link #submission()} is non-null
   */
  public boolean hasParsedSubmission() {
    return submission != null;
  }

  /**
   * Returns the parsed package snapshot when parsing completed.
   *
   * @return optional verified package snapshot
   */
  @SuppressWarnings("unused")
  public Optional<AppSubmissionPackage> parsedSubmission() {
    return Optional.ofNullable(submission);
  }
}
