# Queue Manager App

`apps/queue-manager` stages the first repo-owned AppHost bundle for PR-190.

Build the staged bundle with:

```bash
./gradlew :apps:queue-manager:stageApp
```

The staged output is written to:

```text
apps/queue-manager/build/cryptad-app/queue-manager
```

The staged bundle contains:

```text
cryptad-app.properties
bin/queue-manager.sh
static/README.txt
```

Install it through the existing Platform API by passing the absolute staged directory path:

```bash
curl -X POST \
  --data-urlencode "formPassword=<token>" \
  --data-urlencode "stagedDir=/abs/path/to/apps/queue-manager/build/cryptad-app/queue-manager" \
  http://127.0.0.1:<port>/api/v1/apps/install
```

Start and stop it through the existing app-management routes:

```bash
curl -X POST --data-urlencode "formPassword=<token>" \
  http://127.0.0.1:<port>/api/v1/apps/queue-manager/start

curl -X POST --data-urlencode "formPassword=<token>" \
  http://127.0.0.1:<port>/api/v1/apps/queue-manager/stop
```

The bundle intentionally stays conservative in PR-190:

- Signed app bundles and remote catalogs are deferred.
- App proxying and app-owned static serving are deferred.
- The bundle points `app.ui.entry` at the existing shell-native queue route: `/app/node/#queue`.
- The launcher is a POSIX shell script; Windows-specific first-party app launch packaging remains deferred.
