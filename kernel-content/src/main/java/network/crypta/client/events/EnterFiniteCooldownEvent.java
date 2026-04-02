package network.crypta.client.events;

import network.crypta.support.TimeUtil;

/**
 * Event indicating the client has entered a finite cooldown until a specific time.
 *
 * <p>This event represents a scheduled pause in client activity that is expected to end at a
 * concrete, known instant. It differs from indefinite backoff or paused states by providing an
 * absolute wake-up time, enabling UIs and monitoring components to present an accurate remaining
 * duration and plan subsequent work. Typical usage is to emit an instance on an event bus or to a
 * listener set when the client transitions into cooldown due to backoff policies, rate limiting, or
 * temporary resource constraints.
 *
 * <p>The type is immutable and therefore thread-safe: its sole public field is final and set at
 * construction. The textual description returned by {@link #getDescription()} is computed on each
 * call using the current system clock and {@link TimeUtil#formatTime(long, int, boolean)}, so the
 * formatted remaining time naturally decreases over time. If the configured wake-up time is in the
 * past, the formatted interval may be negative, signaling that the cooldown has already elapsed.
 *
 * <ul>
 *   <li><strong>Responsibility:</strong> carry the absolute wake-up time and expose a concise,
 *       human-friendly description of the remaining delay.
 *   <li><strong>Mutability:</strong> immutable after construction; safe to share across threads.
 *   <li><strong>Identification:</strong> {@link #getCode()} returns a stable, small integer code
 *       for routing and filtering.
 * </ul>
 *
 * @see ClientEvent
 * @see TimeUtil#formatTime(long, int, boolean)
 */
public class EnterFiniteCooldownEvent implements ClientEvent {

  /**
   * Absolute instant when the cooldown ends, in milliseconds since the Unix epoch (UTC).
   *
   * <p>This value is read-only and stable for the lifetime of the object. Consumers typically use
   * it to compute remaining delay as {@code wakeupTime - System.currentTimeMillis()} and display a
   * countdown or schedule work to resume at or after this moment. Values in the past indicate that
   * the cooldown has already expired.
   */
  public final long wakeupTime;

  static final int CODE = 0x10;

  /**
   * Creates an event describing entry into a finite cooldown that ends at the given time.
   *
   * <p>The provided time is stored verbatim as an absolute epoch millisecond value. Callers are
   * responsible for selecting a sensible value; no bounds are enforced here. Passing a value
   * earlier than the current system time is allowed and will result in negative remaining duration
   * in {@link #getDescription()}.
   *
   * @param wakeupTime absolute wake-up time in milliseconds since the Unix epoch (UTC); may be in
   *     the past, present, or future depending on the caller's scheduling needs
   */
  public EnterFiniteCooldownEvent(long wakeupTime) {
    this.wakeupTime = wakeupTime;
  }

  /**
   * Returns a human-friendly description of the remaining time until wake-up.
   *
   * <p>The string is computed relative to the current system clock by formatting {@code (wakeupTime
   * - System.currentTimeMillis())} with two terms and fractional seconds via {@link
   * TimeUtil#formatTime(long, int, boolean)}. As time passes, repeated calls produce updated
   * values. If {@code wakeupTime} is in the past, the formatted interval may include a leading
   * minus sign to indicate that the cooldown has already elapsed.
   *
   * @return a concise English description such as {@code "Wake up in 1m30.000s"}; never {@code
   *     null}
   */
  @Override
  public String getDescription() {
    return "Wake up in " + TimeUtil.formatTime(wakeupTime - System.currentTimeMillis(), 2, true);
  }

  /**
   * Returns a stable, small integer identifying this event type.
   *
   * <p>The value is suitable for lightweight routing, filtering, or serialization schemes that use
   * compact numeric discriminators. It currently returns {@link #CODE} ({@code 0x10}).
   *
   * @return the event code for {@code EnterFiniteCooldownEvent}; the value is constant across
   *     instances
   */
  @Override
  public int getCode() {
    return CODE;
  }
}
