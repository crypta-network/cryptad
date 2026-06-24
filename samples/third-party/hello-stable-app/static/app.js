const status = document.querySelector("#status");
const contractVersion = document.querySelector("#contract-version");
const stableBaseline = document.querySelector("#stable-baseline");
const capabilityCount = document.querySelector("#capability-count");

async function main() {
  const platform = window.CryptaPlatform;
  const bootstrap = await platform.bootstrap.load({ appId: "org.example.hello" });
  const response = await platform.api.get("platform/contract");
  const contract = response.contract || response;
  const baseline = contract.stableBaseline || {};
  const capabilities = Array.isArray(baseline.capabilities) ? baseline.capabilities : [];

  contractVersion.textContent = String(contract.contractVersion || "unknown");
  stableBaseline.textContent = baseline.name || "1.0";
  capabilityCount.textContent =
    capabilities.length > 0 ? String(capabilities.length) : String(baseline.capabilityCount || "unknown");
  status.textContent = `${bootstrap.name} loaded stable Platform API metadata.`;
  status.className = "cr-status cr-status--success sample-status";
}

function showError(error) {
  status.textContent = window.CryptaPlatform.api.errorMessage(error);
  status.className = "cr-status cr-status--danger sample-status";
}

main().catch(showError);
