import fs from 'fs/promises';
import path from 'path';
import axios from 'axios';
import chalk from 'chalk';

const wait = (ms) => new Promise((res) => setTimeout(res, ms));

const chunkArray = (array, chunkSize) => {
  const chunks = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
};

const getAllVendors = async (api, location) => {
  try {
    let hashes = (await fs.readFile(location, 'utf-8')).split(/\n\r?/);
    hashes = hashes.filter((hash) => hash !== '');
    hashes = hashes.map((hash) => hash.trim());
    await fs.appendFile(
      path.join(process.cwd(), 'output.csv'),
      `Name,Hash,Vendor,Category,Engine Name,Engine Version,Result,Method,Engine Update\n`,
      'utf-8',
    );
    try {
      const arrayChunks = chunkArray(hashes, 100);
      for (const chunk of arrayChunks) {
        const requests = chunk.map(async (hash) => {
          return axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: { 'X-Apikey': api },
          });
        });
        const responses = await Promise.all(requests);
        responses.forEach(async (response, index) => {
          const vendors = await response.data.data.attributes.last_analysis_results;
          for (let vendor of Object.entries(vendors)) {
            await fs.appendFile(
              path.join(process.cwd(), 'output.csv'),
              `${response.data.data.attributes.names.toString().replaceAll(',', ';')},${chunk[index]},${vendor[0]},${vendor[1].category},${
                vendor[1].engine_name
              },${vendor[1].engine_version},${vendor[1].result},${vendor[1].method},${vendor[1].engine_update}\n`,
            );
            console.log('✅', chalk.bold.blue('Success:'), 'Result found for', chalk.bold.blue(vendor[0]), 'and sent to output.csv');
          }
          await wait(500);
        });
      }
    } catch (err) {
      console.error('⛔️', chalk.bold.red('Error:'), 'Unable to reach VirusTotal with error message', err.message);
    }
  } catch (err) {
    console.error('⛔️', chalk.bold.red('Error:'), 'Unable to read the hashes file with error message', err.message);
  }
};

export default getAllVendors;
