const assetsData = require("./data");

let cachedVulnerabilities = [];

const isAssetInVulnerability = (assetName, vulnerability) => {
  const vulnDescription = vulnerability.cve.descriptions[0].value.toLowerCase();
  return vulnDescription.includes(assetName.toLowerCase());
};

const filterVulnerabilitiesByAssets = (vulnerabilities, assets) => {
  return vulnerabilities.filter((vulnerability) =>
    assets.some((asset) => isAssetInVulnerability(asset.name, vulnerability))
  );
};

const groupAssetsByTenant = (assets) => {
  return assets.reduce((map, asset) => {
    map[asset.tenantId] = map[asset.tenantId] || [];
    map[asset.tenantId].push(asset);
    return map;
  }, {});
};

const findRelatedAssets = (tenantAssets, vulnerability) => {
  return tenantAssets.filter((asset) =>
    isAssetInVulnerability(asset.name, vulnerability)
  );
};

const addVulnerabilityToResult = (
  result,
  tenantId,
  vulnerability,
  relatedAssets
) => {
  result[tenantId] = result[tenantId] || [];
  result[tenantId].push({
    vulnerabilityId: vulnerability.cve.id,
    assets: relatedAssets.map((asset) => asset.name),
  });
};

const categorizeByTenant = (vulnerabilities, assets) => {
  const tenantAssetsMap = groupAssetsByTenant(assets);
  const result = {};

  for (const vulnerability of vulnerabilities) {
    for (const [tenantId, tenantAssets] of Object.entries(tenantAssetsMap)) {
      const relatedAssets = findRelatedAssets(tenantAssets, vulnerability);
      if (relatedAssets.length > 0) {
        addVulnerabilityToResult(
          result,
          tenantId,
          vulnerability,
          relatedAssets
        );
      }
    }
  }

  return result;
};

const cahceVulnerabilities = (vulnerabilities) => {
  cachedVulnerabilities = vulnerabilities;
  const relevantVulnerabilities = filterVulnerabilitiesByAssets(
    cachedVulnerabilities,
    assetsData.assets
  );

  return categorizeByTenant(relevantVulnerabilities, assetsData.assets);
};

module.exports = { cahceVulnerabilities };
