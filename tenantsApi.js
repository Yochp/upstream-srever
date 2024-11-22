const axios = require("axios");
const nvdConsts = require("./consts");

const fetchVulnerabilities = async () => {
  const url = `${nvdConsts.NVD_URL}?pubStartDate=${nvdConsts.NVD_Params.pubStartDate}&pubEndDate=${nvdConsts.NVD_Params.pubEndDate}&resultsPerPage=${nvdConsts.NVD_Params.resultsPerPage}`;
  try {
    const response = await axios.get(url);
    return response.data.vulnerabilities || [];
  } catch (error) {
    console.error("Error fetching vulnerabilities:", error.message);
  }
};

module.exports = { fetchVulnerabilities };
