const axios = require("axios");
const nvdConsts = require("./consts");

const fetchVulnerabilities = async () => {
  const url = `${nvdConsts.NVD_URL}?pubStartDate=${nvdConsts.NVD_Params.pubStartDate}&pubEndDate=${nvdConsts.NVD_Params.pubEndDate}&resultsPerPage=${nvdConsts.NVD_Params.resultsPerPage}`;
  console.log(url);
  try {
    const response = await axios.get(url);
    // const response = { data: example };
    console.log(response);

    return response.data.vulnerabilities || [];
  } catch (error) {
    console.error("Error fetching vulnerabilities:", error.message);
  }
};

module.exports = { fetchVulnerabilities };

// const example = {
//   resultsPerPage: 10,
//   startIndex: 0,
//   totalResults: 5553,
//   format: "NVD_CVE",
//   version: "2.0",
//   timestamp: "2024-11-22T11:34:36.517",
//   vulnerabilities: [
//     {
//       cve: {
//         id: "CVE-2024-21732",
//         sourceIdentifier: "cve@mitre.org",
//         published: "2024-01-01T08:15:36.087",
//         lastModified: "2024-11-21T08:54:53.800",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "FlyCms through abbaa5a allows XSS via the permission management feature.",
//           },
//           {
//             lang: "es",
//             value:
//               "FlyCms a través de abbaa5a permite XSS a través de la función de permission management.",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
//                 baseScore: 6.1,
//                 baseSeverity: "MEDIUM",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "NONE",
//                 userInteraction: "REQUIRED",
//                 scope: "CHANGED",
//                 confidentialityImpact: "LOW",
//                 integrityImpact: "LOW",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 2.8,
//               impactScore: 2.7,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-79",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria: "cpe:2.3:a:flycms_project:flycms:*:*:*:*:*:*:*:*",
//                     versionEndIncluding: "2019-12-20",
//                     matchCriteriaId: "99EC51C5-F144-4251-A63B-B28AD5E90928",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://github.com/Ghostfox2003/cms/blob/main/1.md",
//             source: "cve@mitre.org",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://github.com/Ghostfox2003/cms/blob/main/1.md",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-5877",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:42.727",
//         lastModified: "2024-11-21T08:42:41.620",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The affiliate-toolkit WordPress plugin before 3.4.3 lacks authorization and authentication for requests to it's affiliate-toolkit-starter/tools/atkp_imagereceiver.php endpoint, allowing unauthenticated visitors to make requests to arbitrary URL's, including RFC1918 private addresses, leading to a Server Side Request Forgery (SSRF) issue.",
//           },
//           {
//             lang: "es",
//             value:
//               "El complemento affiliate-toolkit de WordPress anterior a 3.4.3 carece de autorización y autenticación para solicitudes a su endpoint afiliado-toolkit-starter/tools/atkp_imagereceiver.php, lo que permite a visitantes no autenticados realizar solicitudes a URL arbitrarias, incluidas direcciones privadas RFC1918, lo que genera un problema de Server Side Request Forgery (SSRF).",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//                 baseScore: 9.8,
//                 baseSeverity: "CRITICAL",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "NONE",
//                 userInteraction: "NONE",
//                 scope: "UNCHANGED",
//                 confidentialityImpact: "HIGH",
//                 integrityImpact: "HIGH",
//                 availabilityImpact: "HIGH",
//               },
//               exploitabilityScore: 3.9,
//               impactScore: 5.9,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-862",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:servit:affiliate-toolkit:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "3.4.3",
//                     matchCriteriaId: "E2226746-144C-48DB-99BC-597F58D5D352",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://wpscan.com/vulnerability/39ed4934-3d91-4924-8acc-25759fef9e81",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/39ed4934-3d91-4924-8acc-25759fef9e81",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-6000",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:43.100",
//         lastModified: "2024-11-21T08:42:57.290",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The Popup Builder WordPress plugin before 4.2.3 does not prevent simple visitors from updating existing popups, and injecting raw JavaScript in them, which could lead to Stored XSS attacks.",
//           },
//           {
//             lang: "es",
//             value:
//               "El complemento Popup Builder de WordPress anterior a 4.2.3 no impide que los visitantes simples actualicen las ventanas emergentes existentes e inyecten JavaScript sin formato en ellas, lo que podría provocar ataques XSS almacenados.",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
//                 baseScore: 6.1,
//                 baseSeverity: "MEDIUM",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "NONE",
//                 userInteraction: "REQUIRED",
//                 scope: "CHANGED",
//                 confidentialityImpact: "LOW",
//                 integrityImpact: "LOW",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 2.8,
//               impactScore: 2.7,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-79",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:sygnoos:popup_builder:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "4.2.3",
//                     matchCriteriaId: "7BF7560F-8435-4BB5-9FC7-85C706B4FEB4",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://wpscan.com/blog/stored-xss-fixed-in-popup-builder-4-2-3/",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/cdb3a8bd-4ee0-4ce0-9029-0490273bcfc8",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/blog/stored-xss-fixed-in-popup-builder-4-2-3/",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/cdb3a8bd-4ee0-4ce0-9029-0490273bcfc8",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-6037",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:43.147",
//         lastModified: "2024-11-21T08:43:01.280",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The WP TripAdvisor Review Slider WordPress plugin before 11.9 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)",
//           },
//           {
//             lang: "es",
//             value:
//               "El complemento WP TripAdvisor Review Slider de WordPress anterior a 11.9 no sanitiza ni escapa a algunas de sus configuraciones, lo que podría permitir a usuarios con privilegios elevados, como el administrador, realizar ataques de Cross-Site Scripting almacenado incluso cuando la capacidad unfiltered_html no está permitida (por ejemplo, en una configuración multisitio).",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
//                 baseScore: 4.8,
//                 baseSeverity: "MEDIUM",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "HIGH",
//                 userInteraction: "REQUIRED",
//                 scope: "CHANGED",
//                 confidentialityImpact: "LOW",
//                 integrityImpact: "LOW",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 1.7,
//               impactScore: 2.7,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-79",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:ljapps:wp_tripadvisor_review_slider:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "11.9",
//                     matchCriteriaId: "6F57AC24-433B-4346-A77A-F07252E6A87B",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://wpscan.com/vulnerability/753df046-9fd7-4d15-9114-45cde6d6539b",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/753df046-9fd7-4d15-9114-45cde6d6539b",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-6064",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:43.197",
//         lastModified: "2024-11-21T08:43:04.280",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The PayHere Payment Gateway WordPress plugin before 2.2.12 automatically creates publicly-accessible log files containing sensitive information when transactions occur.",
//           },
//           {
//             lang: "es",
//             value:
//               "El complemento PayHere Payment Gateway de WordPress anterior a 2.2.12 crea automáticamente archivos de registro de acceso público que contienen información confidencial cuando se producen transacciones.",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
//                 baseScore: 7.5,
//                 baseSeverity: "HIGH",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "NONE",
//                 userInteraction: "NONE",
//                 scope: "UNCHANGED",
//                 confidentialityImpact: "HIGH",
//                 integrityImpact: "NONE",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 3.9,
//               impactScore: 3.6,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-532",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:payhere:payhere_payment_gateway:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "2.2.12",
//                     matchCriteriaId: "AE5F697D-75F1-4ADE-90D3-30EE7366E552",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://wpscan.com/vulnerability/423c8881-628b-4380-9677-65b3f5165efe",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/423c8881-628b-4380-9677-65b3f5165efe",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-6113",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:43.243",
//         lastModified: "2024-11-21T08:43:09.477",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The WP STAGING WordPress Backup Plugin before 3.1.3 and WP STAGING Pro WordPress Backup Plugin before 5.1.3 do not prevent visitors from leaking key information about ongoing backups processes, allowing unauthenticated attackers to download said backups later.",
//           },
//           {
//             lang: "es",
//             value:
//               "WP STAGING WordPress Backup Plugin anterior a 3.1.3 y WP STAGING Pro WordPress Backup Plugin anterior a 5.1.3 no impiden que los visitantes filtren información clave sobre los procesos de copia de seguridad en curso, lo que permite a atacantes no autenticados descargar dichas copias de seguridad más tarde.",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
//                 baseScore: 7.5,
//                 baseSeverity: "HIGH",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "NONE",
//                 userInteraction: "NONE",
//                 scope: "UNCHANGED",
//                 confidentialityImpact: "HIGH",
//                 integrityImpact: "NONE",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 3.9,
//               impactScore: 3.6,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "NVD-CWE-noinfo",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:wp-staging:wp_staging:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "3.1.3",
//                     matchCriteriaId: "6249078F-54BE-4941-9345-AD52EBC82EEC",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://research.cleantalk.org/cve-2023-6113-wp-staging-unauth-sensitive-data-exposure-to-account-takeover-poc-exploit/",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/5a71049a-09a6-40ab-a4e8-44634869d4fb",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://research.cleantalk.org/cve-2023-6113-wp-staging-unauth-sensitive-data-exposure-to-account-takeover-poc-exploit/",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/5a71049a-09a6-40ab-a4e8-44634869d4fb",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-6271",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:43.293",
//         lastModified: "2024-11-21T08:43:30.287",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The Backup Migration WordPress plugin before 1.3.6 stores in-progress backups information in easy to find, publicly-accessible files, which may allow attackers monitoring those to leak sensitive information from the site's backups.",
//           },
//           {
//             lang: "es",
//             value:
//               "El complemento Backup Migration de WordPress anterior a 1.3.6 almacena información de las copias de seguridad en progreso en archivos fáciles de encontrar y de acceso público, lo que puede permitir a los atacantes monitorearlos para filtrar información confidencial de las copias de seguridad del sitio. ",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
//                 baseScore: 7.5,
//                 baseSeverity: "HIGH",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "NONE",
//                 userInteraction: "NONE",
//                 scope: "UNCHANGED",
//                 confidentialityImpact: "HIGH",
//                 integrityImpact: "NONE",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 3.9,
//               impactScore: 3.6,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "NVD-CWE-noinfo",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:backupbliss:backup_migration:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "1.3.6",
//                     matchCriteriaId: "B64A4783-7389-43A8-863D-615F1EF7C400",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://research.cleantalk.org/cve-2023-6271-backup-migration-unauth-sensitive-data-exposure-to-full-control-of-the-site-poc-exploit",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/7ac217db-f332-404b-a265-6dc86fe747b9",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://research.cleantalk.org/cve-2023-6271-backup-migration-unauth-sensitive-data-exposure-to-full-control-of-the-site-poc-exploit",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/7ac217db-f332-404b-a265-6dc86fe747b9",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-6421",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:43.347",
//         lastModified: "2024-11-21T08:43:49.450",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The Download Manager WordPress plugin before 3.2.83 does not protect file download's passwords, leaking it upon receiving an invalid one.",
//           },
//           {
//             lang: "es",
//             value:
//               "El complemento Download Manager de WordPress anterior a 3.2.83 no protege las contraseñas de descarga de archivos y las filtra al recibir una no válida.",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
//                 baseScore: 7.5,
//                 baseSeverity: "HIGH",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "NONE",
//                 userInteraction: "NONE",
//                 scope: "UNCHANGED",
//                 confidentialityImpact: "HIGH",
//                 integrityImpact: "NONE",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 3.9,
//               impactScore: 3.6,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-522",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:wpdownloadmanager:wordpress_download_manager:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "3.2.83",
//                     matchCriteriaId: "9EA740C8-DEA3-4F7E-A804-8E59102ECB35",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://wpscan.com/vulnerability/244c7c00-fc8d-4a73-bbe0-7865c621d410",
//             source: "contact@wpscan.com",
//             tags: ["Broken Link", "Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/244c7c00-fc8d-4a73-bbe0-7865c621d410",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Broken Link", "Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2023-6485",
//         sourceIdentifier: "contact@wpscan.com",
//         published: "2024-01-01T15:15:43.393",
//         lastModified: "2024-11-21T08:43:56.757",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "The Html5 Video Player WordPress plugin before 2.5.19 does not sanitise and escape some of its player settings, which combined with missing capability checks around the plugin could allow any authenticated users, such as low as subscribers to perform Stored Cross-Site Scripting attacks against high privilege users like admins",
//           },
//           {
//             lang: "es",
//             value:
//               "El complemento Html5 Video Player de WordPress anterior a 2.5.19 no sanitiza ni escapa a algunas de las configuraciones de su reproductor, lo que, combinado con la falta de comprobaciones de capacidad en torno al complemento, podría permitir que cualquier usuario autenticado, como suscriptores bajos, realice ataques de Cross-Site Scripting almacenado contra usuarios con altos privilegios como administradores",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
//                 baseScore: 5.4,
//                 baseSeverity: "MEDIUM",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "LOW",
//                 userInteraction: "REQUIRED",
//                 scope: "CHANGED",
//                 confidentialityImpact: "LOW",
//                 integrityImpact: "LOW",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 2.3,
//               impactScore: 2.7,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "nvd@nist.gov",
//             type: "Primary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-79",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:bplugins:html5_video_player:*:*:*:*:*:wordpress:*:*",
//                     versionEndExcluding: "2.5.19",
//                     matchCriteriaId: "18C2421F-4BDD-46B6-85AA-C5FDA095A6C8",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://wpscan.com/vulnerability/759b3866-c619-42cc-94a8-0af6d199cc81",
//             source: "contact@wpscan.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://wpscan.com/vulnerability/759b3866-c619-42cc-94a8-0af6d199cc81",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//         ],
//       },
//     },
//     {
//       cve: {
//         id: "CVE-2024-0181",
//         sourceIdentifier: "cna@vuldb.com",
//         published: "2024-01-01T17:15:08.543",
//         lastModified: "2024-11-21T08:46:00.443",
//         vulnStatus: "Modified",
//         descriptions: [
//           {
//             lang: "en",
//             value:
//               "A vulnerability was found in RRJ Nueva Ecija Engineer Online Portal 1.0. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file /admin/admin_user.php of the component Admin Panel. The manipulation of the argument Firstname/Lastname/Username leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-249433 was assigned to this vulnerability.",
//           },
//           {
//             lang: "es",
//             value:
//               "Se encontró una vulnerabilidad en RRJ Nueva Ecija Engineer Online Portal 1.0. Ha sido declarada problemática. Una función desconocida del archivo /admin/admin_user.php del componente Admin Panel es afectada por esta vulnerabilidad. La manipulación del argumento Firstname/Lastname/Username conduce a cross site scripting. El ataque se puede lanzar de forma remota. La explotación ha sido divulgada al público y puede utilizarse. A esta vulnerabilidad se le asignó el identificador VDB-249433.",
//           },
//         ],
//         metrics: {
//           cvssMetricV31: [
//             {
//               source: "cna@vuldb.com",
//               type: "Secondary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N",
//                 baseScore: 2.4,
//                 baseSeverity: "LOW",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "HIGH",
//                 userInteraction: "REQUIRED",
//                 scope: "UNCHANGED",
//                 confidentialityImpact: "NONE",
//                 integrityImpact: "LOW",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 0.9,
//               impactScore: 1.4,
//             },
//             {
//               source: "nvd@nist.gov",
//               type: "Primary",
//               cvssData: {
//                 version: "3.1",
//                 vectorString: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
//                 baseScore: 4.8,
//                 baseSeverity: "MEDIUM",
//                 attackVector: "NETWORK",
//                 attackComplexity: "LOW",
//                 privilegesRequired: "HIGH",
//                 userInteraction: "REQUIRED",
//                 scope: "CHANGED",
//                 confidentialityImpact: "LOW",
//                 integrityImpact: "LOW",
//                 availabilityImpact: "NONE",
//               },
//               exploitabilityScore: 1.7,
//               impactScore: 2.7,
//             },
//           ],
//           cvssMetricV2: [
//             {
//               source: "cna@vuldb.com",
//               type: "Secondary",
//               cvssData: {
//                 version: "2.0",
//                 vectorString: "AV:N/AC:L/Au:M/C:N/I:P/A:N",
//                 baseScore: 3.3,
//                 accessVector: "NETWORK",
//                 accessComplexity: "LOW",
//                 authentication: "MULTIPLE",
//                 confidentialityImpact: "NONE",
//                 integrityImpact: "PARTIAL",
//                 availabilityImpact: "NONE",
//               },
//               baseSeverity: "LOW",
//               exploitabilityScore: 6.4,
//               impactScore: 2.9,
//               acInsufInfo: false,
//               obtainAllPrivilege: false,
//               obtainUserPrivilege: false,
//               obtainOtherPrivilege: false,
//               userInteractionRequired: false,
//             },
//           ],
//         },
//         weaknesses: [
//           {
//             source: "cna@vuldb.com",
//             type: "Secondary",
//             description: [
//               {
//                 lang: "en",
//                 value: "CWE-79",
//               },
//             ],
//           },
//         ],
//         configurations: [
//           {
//             nodes: [
//               {
//                 operator: "OR",
//                 negate: false,
//                 cpeMatch: [
//                   {
//                     vulnerable: true,
//                     criteria:
//                       "cpe:2.3:a:nia:rrj_nueva_ecija_engineer_online_portal:1.0:*:*:*:*:*:*:*",
//                     matchCriteriaId: "23E2E258-3668-43F3-B65F-C8F3B5E8A263",
//                   },
//                 ],
//               },
//             ],
//           },
//         ],
//         references: [
//           {
//             url: "https://mega.nz/file/3Yc2iRzY#Uv7ECzLwUvff__JXEcyPG9oxJ0A1fsBIFGVaS35pvtA",
//             source: "cna@vuldb.com",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://vuldb.com/?ctiid.249433",
//             source: "cna@vuldb.com",
//             tags: ["Third Party Advisory"],
//           },
//           {
//             url: "https://vuldb.com/?id.249433",
//             source: "cna@vuldb.com",
//             tags: ["Third Party Advisory"],
//           },
//           {
//             url: "https://mega.nz/file/3Yc2iRzY#Uv7ECzLwUvff__JXEcyPG9oxJ0A1fsBIFGVaS35pvtA",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Exploit", "Third Party Advisory"],
//           },
//           {
//             url: "https://vuldb.com/?ctiid.249433",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Third Party Advisory"],
//           },
//           {
//             url: "https://vuldb.com/?id.249433",
//             source: "af854a3a-2127-422b-91ae-364da2661108",
//             tags: ["Third Party Advisory"],
//           },
//         ],
//       },
//     },
//   ],
// };
