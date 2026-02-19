package network.crypta.node.updater;

/** Package metadata for a single distributable artifact. */
public record PackageSpec(String chk, Long size, String storeUrl) {}
