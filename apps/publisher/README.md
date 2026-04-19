# Publisher App

`apps/publisher` stages the first repo-owned Publisher AppHost bundle for PR-191.

Build the staged bundle with:

```bash
./gradlew :apps:publisher:stageApp
```

The staged output is written to:

```text
apps/publisher/build/cryptad-app/publisher
```

The staged bundle contains:

```text
cryptad-app.properties
bin/publisher.sh
static/README.txt
```

Install it through the existing Platform API by passing the absolute staged directory path:

```bash
curl -X POST \
  --data-urlencode "formPassword=<token>" \
  --data-urlencode "stagedDir=/abs/path/to/apps/publisher/build/cryptad-app/publisher" \
  http://127.0.0.1:<port>/api/v1/apps/install
```

Start and stop it through the existing app-management routes:

```bash
curl -X POST --data-urlencode "formPassword=<token>" \
  http://127.0.0.1:<port>/api/v1/apps/publisher/start

curl -X POST --data-urlencode "formPassword=<token>" \
  http://127.0.0.1:<port>/api/v1/apps/publisher/stop
```

The bundle intentionally stays conservative in PR-191:

- Signed app bundles and remote catalogs are deferred.
- App proxying and app-owned static serving are deferred.
- The bundle points `app.ui.entry` at the shell-native publisher route: `/app/node/#publisher`.
- The launcher is a POSIX shell script; Windows-specific first-party app launch packaging remains deferred.
