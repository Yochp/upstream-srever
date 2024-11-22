const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_Params = {
  pubStartDate: "2024-01-01T00:00:00.000Z",
  pubEndDate: "2024-03-31T23:59:59.999Z",
  resultsPerPage: 10,
};
module.exports = { NVD_URL, NVD_Params };
