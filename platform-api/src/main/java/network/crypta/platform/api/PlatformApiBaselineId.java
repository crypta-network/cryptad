package network.crypta.platform.api;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jetbrains.annotations.NotNull;

/**
 * Provides a strict, typed identity for a stable Platform API {@code 1.x} compatibility baseline.
 *
 * <p>A baseline ID names an immutable compatibility promise such as {@code 1.0}; it is independent
 * of the URL namespace ({@code /api/v1}), the integer contract version, and the daemon release or
 * build. Parsing deliberately accepts only the canonical decimal form. Whitespace, leading-zero
 * aliases, signs, missing components, and unsupported major lines are rejected so persisted history
 * cannot refer to one baseline through ambiguous spellings.
 *
 * <p>The record is immutable, naturally ordered by major and minor components, and currently
 * limited to the compatible {@code 1.x} line. An incompatible future major belongs to a separate
 * design and potentially a new URL API version.
 *
 * @param major the supported major baseline component, currently exactly {@code 1}
 * @param minor the non-negative minor baseline component
 */
public record PlatformApiBaselineId(int major, int minor)
    implements Comparable<PlatformApiBaselineId> {
  private static final int SUPPORTED_MAJOR = 1;
  private static final Pattern CANONICAL = Pattern.compile("(1)\\.(0|[1-9]\\d*)");

  /**
   * Creates a baseline identity in the supported Platform API {@code 1.x} line.
   *
   * <p>This constructor accepts numeric components for trusted in-process callers. Persisted or
   * user-supplied text should pass through {@link #parse(String)} so aliases such as leading-zero
   * minor versions are rejected before construction. Successful instances are immutable and use
   * numeric ordering rather than lexical version ordering.
   *
   * @throws IllegalArgumentException if the major is unsupported or the minor is negative
   */
  public PlatformApiBaselineId {
    if (major != SUPPORTED_MAJOR) {
      throw new IllegalArgumentException("only Platform API 1.x baseline identities are supported");
    }
    if (minor < 0) {
      throw new IllegalArgumentException("baseline minor version must not be negative");
    }
  }

  /**
   * Parses an exact canonical identity such as {@code 1.0}; aliases are rejected.
   *
   * <p>The parser does not trim input and accepts only unsigned decimal components in the supported
   * major line. The returned value can be compared or serialized without retaining the original
   * text. Excessively large components fail as malformed identities rather than wrapping numeric
   * values.
   *
   * @param value the exact baseline text with no surrounding whitespace or leading-zero alias
   * @return the typed identity represented by the canonical text
   * @throws IllegalArgumentException if the text is malformed, ambiguous, or outside {@code 1.x}
   */
  public static PlatformApiBaselineId parse(String value) {
    String text = Objects.requireNonNull(value, "value");
    Matcher matcher = CANONICAL.matcher(text);
    if (!matcher.matches()) {
      throw new IllegalArgumentException("invalid Platform API 1.x baseline identity: " + text);
    }
    try {
      return new PlatformApiBaselineId(
          Integer.parseInt(matcher.group(1)), Integer.parseInt(matcher.group(2)));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("invalid Platform API 1.x baseline identity: " + text, e);
    }
  }

  /**
   * Compares baseline identities by numeric major component and then numeric minor component.
   *
   * <p>The ordering is consistent with record equality and places {@code 1.10} after {@code 1.2},
   * independent of lexical string order. The current type admits only major version {@code 1}, but
   * retaining both comparisons makes the ordering definition explicit.
   *
   * @param other the non-null baseline identity to compare with this identity
   * @return a negative value, zero, or a positive value according to numeric version order
   * @throws NullPointerException if {@code other} is {@code null}
   */
  @Override
  public int compareTo(@NotNull PlatformApiBaselineId other) {
    int majorComparison = Integer.compare(major, Objects.requireNonNull(other, "other").major);
    return majorComparison != 0 ? majorComparison : Integer.compare(minor, other.minor);
  }

  /**
   * Returns the canonical decimal representation of this baseline identity.
   *
   * <p>The result contains the numeric major and minor components separated by one period, with no
   * whitespace, sign, or leading-zero alias. It is suitable for deterministic registry JSON and
   * round-trips through {@link #parse(String)}.
   *
   * @return the canonical baseline identity in {@code major.minor} form
   */
  @Override
  public @NotNull String toString() {
    return major + "." + minor;
  }
}
