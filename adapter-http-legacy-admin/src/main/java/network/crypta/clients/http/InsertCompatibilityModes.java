package network.crypta.clients.http;

import java.util.List;
import java.util.Objects;

/**
 * Detached HTTP-local compatibility-mode names used by the legacy insert forms.
 *
 * <p>This record is the shell-facing representation of the compatibility-mode choices that appear
 * in legacy upload and queue forms. The admin-owned HTTP code only needs stable display names, the
 * ordering of those names, and the default selection to preselect in generated HTML. It does not
 * need the runtime-node enum itself, nor the broader insert-context behavior behind that enum.
 *
 * <p>Keeping those values in a small HTTP-local record narrows the remaining bridge seam. Runtime
 * wiring can translate from the live daemon-side compatibility enum into this record once during
 * bootstrap, while admin toadlets stay coupled only to plain strings and ordering rules. The record
 * does not attempt to interpret or normalize the supplied names. Callers are expected to provide
 * already-normalized values in user-visible order and to supply a default name that is meaningful
 * for the same rendered choice set.
 *
 * @param supportedModeNames ordered compatibility-mode names presented to users in legacy HTTP
 *     forms; the record preserves this order exactly
 * @param defaultModeName compatibility-mode name selected by default when the shell renders a new
 *     form
 */
public record InsertCompatibilityModes(List<String> supportedModeNames, String defaultModeName) {
  /**
   * Creates a validated detached compatibility-mode bundle.
   *
   * <p>The constructor performs only structural validation and defensive copying. It ensures the
   * record never stores {@code null} references and that later mutations to the caller-provided
   * list cannot change the HTTP shell's view of the compatibility choices. It intentionally does
   * not enforce that {@code defaultModeName} appears in {@code supportedModeNames}; callers are
   * responsible for supplying a coherent set of values.
   *
   * @param supportedModeNames ordered compatibility-mode names to present to the user; copied into
   *     an unmodifiable list for stable later reads
   * @param defaultModeName compatibility-mode name selected by default in the form; stored exactly
   *     as supplied
   * @throws NullPointerException if either argument is {@code null}
   */
  public InsertCompatibilityModes(List<String> supportedModeNames, String defaultModeName) {
    this.supportedModeNames = List.copyOf(Objects.requireNonNull(supportedModeNames));
    this.defaultModeName = Objects.requireNonNull(defaultModeName);
  }
}
