const fs = require('fs');
const axios = require('axios');
const AdmZip = require('adm-zip');

// The OSV public buckets we want to monitor
const ECOSYSTEMS = ['npm', 'PyPI']; 
const OSV_BASE_URL = 'https://osv-vulnerabilities.storage.googleapis.com';

async function generateThreatFeed() {
  console.log('Starting Threat Intelligence Feed Generation...');
  const catalog = {
    schema_version: "0.1.0",
    last_updated: new Date().toISOString(),
    entries: []
  };

  for (const ecosystem of ECOSYSTEMS) {
    console.log(`\nFetching latest vulnerabilities for ${ecosystem}...`);
    const zipUrl = `${OSV_BASE_URL}/${ecosystem}/all.zip`;

    try {
      // 1. Download the ecosystem zip file into memory
      const response = await axios.get(zipUrl, { responseType: 'arraybuffer' });
      const zip = new AdmZip(response.data);
      const zipEntries = zip.getEntries();
      
      console.log(`Unpacking ${zipEntries.length} advisories for ${ecosystem}...`);

      // 2. Parse the files (Limiting to recent/latest 1000 for performance in this MVP)
      // In a production app, you would parse all of them or filter by the 'modified' date
      const recentEntries = zipEntries.slice(0, 1000); 

      for (const entry of recentEntries) {
        if (!entry.entryName.endsWith('.json')) continue;

        const rawData = zip.readAsText(entry);
        const osvRecord = JSON.parse(rawData);

        // 3. Transform: Map the dense OSV schema into our lightweight Bumblebee schema
        if (osvRecord.affected && osvRecord.affected.length > 0) {
          osvRecord.affected.forEach(affectedItem => {
            if (affectedItem.package && affectedItem.package.name) {
              
              // Extract the affected versions (if available)
              const versions = affectedItem.versions || [];

              if (versions.length === 0) {
                return; // Skips to the next affected item
              }
              
              // Push the clean record to our catalog
              catalog.entries.push({
                id: osvRecord.id,
                package: affectedItem.package.name,
                ecosystem: affectedItem.package.ecosystem,
                summary: osvRecord.summary || 'Malicious package or vulnerability detected',
                versions: versions,
                severity: extractSeverity(osvRecord)
              });
            }
          });
        }
      }
    } catch (error) {
      console.error(`Failed to process ${ecosystem}:`, error.message);
    }
  }

  // Include entries in the catalog with severity "CRITICAL"
  catalog.entries = catalog.entries.filter(entry => entry.severity === "CRITICAL");

  // 4. Write the final transformed JSON to disk
  fs.writeFileSync('catalog.json', JSON.stringify(catalog, null, 2));
  console.log(`\nSuccess! Generated catalog.json with ${catalog.entries.length} threat entries.`);
}

// Helper to safely extract severity, defaulting to HIGH if unknown
function extractSeverity(osvRecord) {
  if (osvRecord.database_specific && osvRecord.database_specific.severity) {
    return osvRecord.database_specific.severity;
  }
  return "HIGH"; 
}

// Execute the script
generateThreatFeed();