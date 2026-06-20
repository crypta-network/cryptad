package network.crypta.platform.api.consent;

import java.util.LinkedHashSet;
import java.util.List;

/**
 * Shared policy helpers for deriving snapshot risk and automation gates from consent sections.
 *
 * <p>The consent service builds findings in feature-specific helpers, then uses this class to apply
 * the small cross-cutting policy that every snapshot needs: maximum risk and stable reason codes
 * for material or blocking findings. Keeping this logic in one place avoids Web Shell, scheduler,
 * and route code disagreeing about which findings require an operator approval.
 *
 * <p>The helper is stateless and deterministic. It reads already-normalized sections and does not
 * inspect raw app manifests, catalog entries, service request bodies, or migration plans.
 */
public final class ConsentPolicy {
  private ConsentPolicy() {}

  /**
   * Returns the maximum section risk.
   *
   * <p>Snapshots use this rollup to decide whether the action is informational, material, or
   * blocking. Empty section lists produce {@link ConsentRiskLevel#NONE}.
   *
   * @param sections consent sections to aggregate in display order
   * @return highest risk level present in the sections
   */
  public static ConsentRiskLevel riskLevel(List<ConsentSection> sections) {
    ConsentRiskLevel risk = ConsentRiskLevel.NONE;
    for (ConsentSection section : sections) {
      risk = ConsentRiskLevel.max(risk, section.riskLevel());
    }
    return risk;
  }

  /**
   * Returns stable reason codes for material or blocking findings.
   *
   * <p>The returned list preserves first-seen order while removing duplicates. These codes become
   * the snapshot's blocking or consent-required reasons and are safe to expose as machine-readable
   * API fields.
   *
   * @param sections consent sections whose findings should be scanned
   * @return unique finding codes whose risk level requires approval or blocks the action
   */
  public static List<String> blockingReasons(List<ConsentSection> sections) {
    LinkedHashSet<String> reasons = new LinkedHashSet<>();
    for (ConsentSection section : sections) {
      for (ConsentFinding item : section.items()) {
        if (item.riskLevel().requiresApproval()) {
          reasons.add(item.code());
        }
      }
    }
    return List.copyOf(reasons);
  }
}
