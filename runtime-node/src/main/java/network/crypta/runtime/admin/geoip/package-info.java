/**
 * Tiny runtime-owned GeoIP seam used by legacy admin-page adapters.
 *
 * <p>The types in this package let {@code network.crypta.runtime.admin} render country names and
 * optional flag URLs without importing HTTP GeoIP implementation classes from {@code
 * network.crypta.clients.http}. The seam intentionally stays narrow so the legacy connections page
 * can preserve its existing HTML while the broader runtime and HTTP decoupling work continues.
 *
 * <p>The package owns two small concepts:
 *
 * <ul>
 *   <li>a detached country DTO carrying only UI-facing display data
 *   <li>a best-effort lookup interface that runtime-admin can depend on without knowing how the
 *       GeoIP database is loaded or queried
 * </ul>
 *
 * <p>That ownership split keeps the legacy page behavior stable while making the remaining HTTP
 * bridge explicit and easy to replace in later extraction work.
 */
package network.crypta.runtime.admin.geoip;
