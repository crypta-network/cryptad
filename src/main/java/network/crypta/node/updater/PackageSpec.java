package network.crypta.node.updater;

/**
 * Metadata describing one distributable package artifact in core updater descriptors.
 *
 * <p>Each instance represents a concrete package option associated with a platform key (for
 * example, architecture plus extension) in core update info descriptors. The descriptor may point
 * to a directly downloadable CHK payload and/or to a store URL used when package installation is
 * delegated to a system store workflow.
 *
 * @param chk optional CHK URI string for direct package download
 * @param size optional package size in bytes when known
 * @param storeUrl optional store page URL or install target reference
 */
public record PackageSpec(String chk, Long size, String storeUrl) {}
