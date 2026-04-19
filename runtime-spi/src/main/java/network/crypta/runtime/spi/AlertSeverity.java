package network.crypta.runtime.spi;

/**
 * Detached alert severity mapped from the runtime's legacy user-alert priority classes.
 *
 * <p>This enum provides the stable severity vocabulary that higher layers use when rendering or
 * summarizing alerts. It is deliberately separate from the runtime alert interfaces so Platform
 * API, the Web Shell, and other detached consumers can classify alerts without importing
 * daemon-owned types. The mapping remains one-to-one with the legacy short-valued priority classes
 * already used inside the runtime.
 *
 * <p>The declaration order is descriptive only. Callers must not infer ordering or persistence
 * semantics from the enum ordinal. Use {@link #priorityClass()} when a legacy numeric value is
 * required, or compare explicit enum constants when choosing the highest visible severity.
 */
public enum AlertSeverity {
  /**
   * An error that requires immediate attention.
   *
   * <p>Consumers should treat this as the most urgent alert class and render it with the strongest
   * emphasis available to that surface.
   */
  CRITICAL_ERROR((short) 0),

  /**
   * A serious error that may still allow some operation.
   *
   * <p>This severity still indicates operator action is likely needed, but it is below {@link
   * #CRITICAL_ERROR} in urgency.
   */
  ERROR((short) 1),

  /**
   * A warning about degraded operation or reduced anonymity.
   *
   * <p>Warnings normally indicate reduced quality, capacity, or safety rather than an outright
   * failure.
   */
  WARNING((short) 2),

  /**
   * A minor informational alert.
   *
   * <p>Consumers may render this class less prominently than error and warning severities.
   */
  MINOR((short) 3);

  private final short priorityClass;

  AlertSeverity(short priorityClass) {
    this.priorityClass = priorityClass;
  }

  /**
   * Returns the legacy user-alert priority class represented by this detached severity.
   *
   * <p>The value matches the short constant expected by the existing runtime alert machinery. This
   * method exists for callers that need to compare or persist the legacy representation without
   * depending on runtime-owned alert constants.
   *
   * @return legacy priority-class value used by the daemon alert manager
   */
  public short priorityClass() {
    return priorityClass;
  }

  /**
   * Maps a legacy priority class to the detached severity enum.
   *
   * <p>This is the normalization point between the runtime's historic short constants and the
   * detached enum contract used elsewhere. Callers should pass only values produced by the runtime
   * alert system.
   *
   * @param priorityClass legacy user-alert priority class
   * @return detached severity matching the supplied legacy value
   * @throws IllegalArgumentException when the supplied value is not recognized
   */
  public static AlertSeverity fromPriorityClass(short priorityClass) {
    return switch (priorityClass) {
      case 0 -> CRITICAL_ERROR;
      case 1 -> ERROR;
      case 2 -> WARNING;
      case 3 -> MINOR;
      default ->
          throw new IllegalArgumentException("Unknown alert priority class: " + priorityClass);
    };
  }
}
