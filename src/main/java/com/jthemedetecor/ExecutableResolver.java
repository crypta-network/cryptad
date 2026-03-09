/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

package com.jthemedetecor;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;
import org.jetbrains.annotations.Nullable;

/**
 * Resolves helper executable names against the process search path.
 *
 * <p>The vendored theme detectors use this helper to keep platform command lookup behavior explicit
 * while still preserving the launcher's historical compatibility with non-standard installations.
 * Resolution prefers concrete executable paths when a non-blank {@code PATH} value is available,
 * but it deliberately falls back to bare command names when {@code PATH} is absent so the operating
 * system can apply its default search semantics.
 *
 * <p>The methods in this class are purely functional and do not cache results. Callers that probe
 * multiple candidate names can preserve their preferred priority order by passing candidates in the
 * order they want them returned.
 */
final class ExecutableResolver {
  /** Environment variable name used to discover executable search directories. */
  private static final String PATH_ENVIRONMENT_VARIABLE = "PATH";

  /**
   * Pattern that splits {@code PATH} while preserving empty segments for current-directory lookup.
   */
  private static final Pattern PATH_ENTRY_SEPARATOR =
      Pattern.compile(Pattern.quote(File.pathSeparator));

  /** Prevents instantiation of this static utility class. */
  private ExecutableResolver() {}

  /**
   * Resolves an executable name against the current process {@code PATH}.
   *
   * <p>If {@code PATH} is missing or blank, this method returns the bare executable name unchanged
   * so callers can defer lookup to the operating system's default process-launch rules. When {@code
   * PATH} is present, the first executable file found in search order is returned.
   *
   * @param executableName executable file name to resolve for process creation
   * @return an absolute executable path, or the bare executable name when {@code PATH} is blank
   * @throws IOException if {@code PATH} is present but no matching executable can be found on it
   */
  static String resolveFromPath(String executableName) throws IOException {
    return resolveFromPath(executableName, System.getenv(PATH_ENVIRONMENT_VARIABLE));
  }

  /**
   * Resolves an executable name against a caller-supplied search path string.
   *
   * <p>An empty or blank path preserves the original executable name, so callers can still rely on
   * platform-default command lookup. Otherwise, the path is searched left to right, and the first
   * executable file match is returned as an absolute path.
   *
   * @param executableName executable file name to resolve for later process creation
   * @param path search path string using the platform path separator or blank to preserve the bare
   *     executable name
   * @return an absolute executable path, or {@code executableName} when the supplied path is blank
   * @throws IOException if the supplied non-blank path does not contain the requested executable
   */
  static String resolveFromPath(String executableName, @Nullable String path) throws IOException {
    if (path == null || path.isBlank()) {
      return executableName;
    }

    for (String pathEntry : PATH_ENTRY_SEPARATOR.split(path, -1)) {
      File executable =
          pathEntry.isEmpty() ? new File(executableName) : new File(pathEntry, executableName);
      if (executable.isFile() && executable.canExecute()) {
        return executable.getAbsolutePath();
      }
    }

    throw new IOException(String.format("Unable to locate %s on %s", executableName, path));
  }

  /**
   * Resolves the highest-priority executable from a list of candidate names.
   *
   * <p>Candidates are evaluated in the order they appear in {@code executableNames}. The first
   * resolvable candidate is returned, which lets callers express version preferences such as trying
   * a newer helper binary before falling back to an older name.
   *
   * @param executableNames ordered candidate executable names to probe
   * @param path search path string using the platform path separator or blank to preserve the
   *     candidate names as-is
   * @return the first candidate that can be resolved successfully
   * @throws IOException if no candidate can be resolved from a non-blank search path
   */
  static String resolveFirstFromPath(List<String> executableNames, @Nullable String path)
      throws IOException {
    return resolveCandidatesFromPath(executableNames, path).getFirst();
  }

  /**
   * Resolves every candidate executable that can be found on the supplied search path.
   *
   * <p>When {@code path} is blank, the original candidate list is returned unchanged so callers can
   * hand those names directly to {@link ProcessBuilder}. Otherwise, each name is resolved
   * independently and successful matches are returned in the same relative order as the input.
   *
   * @param executableNames ordered candidate executable names to probe
   * @param path search path string using the platform path separator or blank to preserve the
   *     candidate names unchanged
   * @return an immutable list containing each resolvable candidate in input order
   * @throws IOException if a non-blank path is supplied, and none of the candidates can be resolved
   */
  static List<String> resolveCandidatesFromPath(List<String> executableNames, @Nullable String path)
      throws IOException {
    Objects.requireNonNull(executableNames);
    if (path == null || path.isBlank()) {
      return List.copyOf(executableNames);
    }

    List<String> resolvedExecutables = new ArrayList<>();
    IOException lastFailure = null;
    for (String executableName : executableNames) {
      try {
        resolvedExecutables.add(resolveFromPath(executableName, path));
      } catch (IOException e) {
        lastFailure = e;
      }
    }

    if (!resolvedExecutables.isEmpty()) {
      return List.copyOf(resolvedExecutables);
    }

    throw new IOException(
        String.format("Unable to locate any of %s on %s", executableNames, path), lastFailure);
  }
}
