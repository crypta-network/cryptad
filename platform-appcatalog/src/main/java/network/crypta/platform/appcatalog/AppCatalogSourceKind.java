package network.crypta.platform.appcatalog;

/**
 * Transport family used by a configured signed app catalog source.
 *
 * <p>The kind describes how catalog properties and signature sidecars are fetched. It is not a
 * trust decision. Every source kind still feeds the same signed-catalog verifier, and catalog keys
 * remain the authority for accepting catalog metadata. The enum exists so managers, stores, API
 * responses, and shell UI can talk about source behavior without repeatedly parsing URI schemes.
 *
 * <p>{@link #HTTP} is intentionally narrower than a generic web source: app catalogs only accept
 * loopback HTTP for local development. Public remote distribution should use {@link #HTTPS} or
 * {@link #CRYPTA}; local operator-managed files use {@link #FILE}.
 */
public enum AppCatalogSourceKind {
  /**
   * Local filesystem source represented as a {@code file:} URI.
   *
   * <p>This kind covers operator-managed catalog files on the node host. The source is fetched from
   * local storage, but signatures are still verified before the catalog can replace stored state.
   */
  FILE,

  /**
   * Loopback-only plaintext development source represented as an {@code http:} URI.
   *
   * <p>Only localhost-style hosts are accepted for this kind. It is useful for local tooling and
   * tests, not for public catalog distribution.
   */
  HTTP,

  /**
   * Remote TLS source represented as an {@code https:} URI.
   *
   * <p>This kind fetches catalog sidecars over HTTPS. TLS protects the transport, while catalog
   * signatures still provide the application-level authenticity check.
   */
  HTTPS,

  /**
   * Crypta content source represented as a {@code crypta:} URI.
   *
   * <p>This kind fetches catalog sidecars through the runtime content-fetch port. Crypta keys are
   * treated as transport locations; signed catalog verification remains mandatory.
   */
  CRYPTA
}
