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

final class ExecutableResolver {
  private static final String PATH_ENVIRONMENT_VARIABLE = "PATH";
  private static final Pattern PATH_ENTRY_SEPARATOR =
      Pattern.compile(Pattern.quote(File.pathSeparator));

  private ExecutableResolver() {}

  static String resolveFromPath(String executableName) throws IOException {
    return resolveFromPath(executableName, System.getenv(PATH_ENVIRONMENT_VARIABLE));
  }

  static String resolveFirstFromPath(List<String> executableNames) throws IOException {
    return resolveFirstFromPath(executableNames, System.getenv(PATH_ENVIRONMENT_VARIABLE));
  }

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

  static String resolveFirstFromPath(List<String> executableNames, @Nullable String path)
      throws IOException {
    return resolveCandidatesFromPath(executableNames, path).get(0);
  }

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
