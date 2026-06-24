# Third-party Hello Stable SDK example

This example shows the browser SDK pattern used by the `hello-stable` template and the checked-in
sample at `samples/third-party/hello-stable-app/`. It reads stable Platform API contract metadata
and handles errors without logging raw tokens or private data.

The stable SDK call is `CryptaPlatform.api.get("platform/contract")`; the sample assigns
`window.CryptaPlatform` to `platform` before making that call.

```html
<script src="./crypta-platform.js"></script>
<script type="module" src="./app.js"></script>
```

```js
const status = document.querySelector("#status");
const contractVersion = document.querySelector("#contract-version");

async function main() {
  const platform = window.CryptaPlatform;
  const bootstrap = await platform.bootstrap.load({ appId: "org.example.hello" });
  const response = await platform.api.get("platform/contract");
  const contract = response.contract || response;

  contractVersion.textContent = String(contract.contractVersion || "unknown");
  status.textContent = `${bootstrap.name} loaded stable Platform API metadata.`;
}

function showError(error) {
  status.textContent = window.CryptaPlatform.api.errorMessage(error);
}

main().catch(showError);
```

The app declares:

```properties
api.targetStability=stable
api.experimentalCapabilitiesAccepted=false
app.permissions=platform.contract.read
```

Run local checks before packaging:

```bash
mkdir -p ../artifacts
crypta-app test --bundle-dir . --strict
crypta-app ui lint --bundle-dir . --strict
crypta-app api snapshot --output ../artifacts/platform-api-contract.json
crypta-app compat verify --bundle-dir . --contract ../artifacts/platform-api-contract.json --strict
```

Do not log browser session tokens, bearer tokens, authorization headers, private insert URIs, raw
fetched content, raw app data, or local absolute paths. Use app ids, capability names, status
values, and digests in issue reports.
