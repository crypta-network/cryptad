package network.crypta.runtime.persistence;

import java.io.File;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;

/**
 * Parameter bundle for configuring a {@link ConfigurablePersister}.
 *
 * @param nodeConfig configuration section that stores the file path option
 * @param optionName key used to register the configurable file path
 * @param defaultFilename default filename joined with {@code baseDir}
 * @param optionMeta metadata for the option (ordering, expert flag, descriptions)
 * @param baseDir directory used to resolve {@code defaultFilename}
 */
public record ConfigurablePersisterParams(
    SubConfig nodeConfig,
    String optionName,
    String defaultFilename,
    Option.Meta optionMeta,
    File baseDir) {}
