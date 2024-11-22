const express = require("express");
const cors = require("cors");
const tenantsApi = require("./tenantsApi");
const tenantsService = require("./tenantsService");

const app = express();

const PORT = process.env.PORT || 3001;

const allowedOrigins = ["http://localhost:5173", "http://localhost:3000"];
app.use(
  cors({
    origin: allowedOrigins,
  })
);

app.use(express.json());

let categorizedData;
const loadVulnerabilities = async () => {
  try {
    vulnerabilities = await tenantsApi.fetchVulnerabilities();
    if (vulnerabilities) {
      categorizedData = tenantsService.cahceVulnerabilities(vulnerabilities);
    }
  } catch (error) {
    console.error("Error loading vulnerabilities:", error.message);
  }
};

loadVulnerabilities();

app.get("/vulnerabilities/:id", (req, res) => {
  try {
    const id = req.params.id;
    res.json(categorizedData[id] || []);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/", (req, res) => {
  res.send("Upstream Server is running!!!");
});

app.listen(PORT, () => {
  console.log(`Server is running on port - ${PORT}`);
});
