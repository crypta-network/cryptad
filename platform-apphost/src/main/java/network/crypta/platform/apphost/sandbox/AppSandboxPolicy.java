package network.crypta.platform.apphost.sandbox;

import java.util.Objects;
import network.crypta.platform.appdist.AppSandboxMode;

/**
 * Normalized sandbox policy requested by an app manifest.
 *
 * <p>The policy captures only the app author's request. Runtime support and whether any isolation
 * is active are reported through {@link AppSandboxStatus} after provider selection.
 *
 * <p>AppHost derives this record from the signed bundle manifest fields {@code sandbox.mode} and
 * {@code sandbox.required}. It is intentionally small: it does not include network, filesystem, or
 * restart-policy hints that AppHost cannot enforce in PR-206. Provider selection uses the mode to
 * choose a launch planner and the requirement to decide whether an unsupported mode may degrade to
 * a warning or must reject launch. The record is immutable and safe to carry in installed-app
 * snapshots, runtime records, and Platform API summaries.
 *
 * @param mode requested sandbox mode from the app manifest
 * @param requirement whether unsupported requested modes must fail launch
 */
public record AppSandboxPolicy(AppSandboxMode mode, AppSandboxRequirement requirement) {
  /**
   * Creates a normalized sandbox policy.
   *
   * <p>Null values are normalized to the backward-compatible manifest defaults: {@link
   * AppSandboxMode#NONE} and {@link AppSandboxRequirement#OPTIONAL}. That keeps older programmatic
   * callers source-compatible while ensuring downstream provider logic never receives a null policy
   * component.
   */
  public AppSandboxPolicy {
    mode = Objects.requireNonNullElse(mode, AppSandboxMode.NONE);
    requirement = Objects.requireNonNullElse(requirement, AppSandboxRequirement.OPTIONAL);
  }

  /**
   * Creates a policy from manifest fields.
   *
   * <p>This overload mirrors the parsed manifest shape. It is useful at the boundary between {@code
   * platform-appdist}, where {@code sandbox.required} is a boolean property, and AppHost, where the
   * requirement is represented as a typed value.
   *
   * @param mode requested sandbox mode from {@code sandbox.mode}
   * @param required manifest {@code sandbox.required} value after boolean validation
   */
  public AppSandboxPolicy(AppSandboxMode mode, boolean required) {
    this(mode, AppSandboxRequirement.fromBoolean(required));
  }

  /**
   * Returns the backward-compatible default policy.
   *
   * <p>Missing sandbox fields in existing manifests map to this value. It requests the normal local
   * process launch path and allows launch to proceed without provider-enforced isolation.
   *
   * @return no-sandbox, optional policy used when manifest sandbox fields are absent
   */
  public static AppSandboxPolicy defaults() {
    return new AppSandboxPolicy(AppSandboxMode.NONE, AppSandboxRequirement.OPTIONAL);
  }

  /**
   * Returns whether unsupported sandbox support must fail launch.
   *
   * <p>This is a convenience bridge for existing code paths that only need the manifest boolean
   * semantics. It does not indicate that a provider has enforced isolation; use {@link
   * AppSandboxStatus#supportLevel()} for the runtime result.
   *
   * @return {@code true} when the app requires the requested sandbox mode to be supported
   */
  public boolean required() {
    return requirement.required();
  }
}
