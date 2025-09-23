# Generator (Legacy GWT Client)

## Overview

The `generator/` directory contains a legacy Google Web Toolkit (GWT) client used by the HTTP interface (often called "fproxy") to provide dynamic, client‑side updates. It originates from the historical Freenet UI code and compiles Java sources into JavaScript assets that the daemon serves to browsers.

Today, these precompiled assets are already checked into `src/main/resources` and loaded by the web UI. The `generator/` sources are retained for reference and potential regeneration but are not wired into the Gradle build.

## What’s Inside

- `generator/js/src/freenet/FreenetJs.gwt.xml`: GWT module descriptor with `rename-to='freenetjs'` and entry point `freenet.client.FreenetJs`.
- Client code packages:
  - `freenet.client.*`: entry point and glue code.
  - `freenet.client.connection.*`: keepalive, long‑poll, and shared connection managers.
  - `freenet.client.updaters.*`: DOM updaters for progress bars, images, connection list, etc.
  - `freenet.client.tools.*`: simple utilities (AJAX helper, Base64, query parameters).
  - `freenet.client.l10n.*`: in‑browser localization mapping.
- Tests: `generator/js/tests` contains HtmlUnit‑based “push” tests (e.g., `PushTester`) for the dynamic update pipeline.

## Generated Assets

The GWT compiler produces a module named `freenetjs` whose output is already checked in here:

- `src/main/resources/network/crypta/clients/http/staticfiles/freenetjs/`

Key files include:

- `freenetjs.nocache.js` – GWT bootstrap script that selects the correct permutation.
- `*.cache.html` – optimized, permutation‑specific compiled JS payloads.
- `clear.cache.gif` and small `*.cache.png` resources – bootstrap cache markers and assets.
- `hosted.html` – legacy GWT development/hosted‑mode helper page.

## Where It’s Used

Server‑side code injects the bootstrap script into HTML when web‑pushing is enabled:

- `PageMaker` – adds `<script src="/static/freenetjs/freenetjs.nocache.js">` to the page head.
- `PushingTagReplacerCallback` – inserts the same script into proxied pages and provides client‑side l10n.

These resolve to the static resources under `staticfiles/freenetjs` at runtime.

## Build Status and Rationale

- Not part of the Gradle build: The daemon ships with the prebuilt assets; the GWT sources are maintained for historical context and potential regeneration.
- Legacy stack: The code targets an old GWT toolchain and browser model. Treat as archival unless a concrete need arises to change the client‑side behavior.

## Regenerating (Advanced, Optional)

Only attempt if you genuinely need to change the client helpers and understand GWT:

1. Obtain a compatible GWT SDK (the sources reference GWT around 2.4–era APIs).
2. Compile the module `freenet.FreenetJs` with the GWT compiler, setting the output directory to a temporary location.
   - Example (adjust paths and SDK):
     - `java -Xmx1G -cp <gwt-sdk>/gwt-dev.jar:<gwt-sdk>/gwt-user.jar:<src_paths> com.google.gwt.dev.Compiler freenet.FreenetJs -war /tmp/freenetjs-out`
3. Copy the produced artifacts into `src/main/resources/network/crypta/clients/http/staticfiles/freenetjs/`:
   - `freenetjs.nocache.js`, `*.cache.html`, `clear.cache.gif`, and any small `*.cache.png` files.
4. Verify the UI loads and push updates work (status bar messages, progress bars, keepalive) before committing.

Notes:
- Expect toolchain friction on modern JDKs; you may need to build with an older Java version that the GWT compiler supports, then run the daemon with Java 21+.
- Keep the output exactly under the `freenetjs/` directory to match URL paths the server emits.

## Testing Hints

- The HtmlUnit tests in `generator/js/tests` are intended for the legacy pipeline and expect a node running at `http://127.0.0.1:8888`. They are not integrated into Gradle.
- For runtime verification, enable JavaScript and web‑pushing in the HTTP interface and observe that incremental updates (messages, progress, images) occur without page reloads.

## Caveats

- Security/maintenance: GWT hosted/dev mode and older permutations are not maintained; prefer minimal changes.
- Backward compatibility: Any change to the generated assets can affect the HTTP client behavior; test thoroughly across the UI.

