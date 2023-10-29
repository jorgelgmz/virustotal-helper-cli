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

const simpleVendor = async (api, location) => {
  try {
    let hashes = (await fs.readFile(location, 'utf-8')).split(/\n\r?/);
    hashes = hashes.filter((hash) => hash !== '');
    hashes = hashes.map((hash) => hash.trim());
    await fs.appendFile(path.join(process.cwd(), 'output.csv'), `Hash,CrowdStrike,SentinelOne,Microsoft\n`, 'utf-8');
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
          const scanners = await response.data.data.attributes.last_analysis_results;
          await fs.appendFile(
            path.join(process.cwd(), 'output.csv'),
            `${chunk[index]},${scanners.CrowdStrike?.category === undefined ? 'unknown' : scanners.CrowdStrike.category},${
              scanners.SentinelOne?.category === undefined ? 'unknown' : scanners.SentinelOne.category
            },${scanners.Microsoft?.category === undefined ? 'unknown' : scanners.Microsoft.category}\n`,
          );
          console.log(
            '✅',
            chalk.bold.blue('Success:'),
            'CrowdStrike, SentinelOne, and Microsoft detections for',
            chalk.bold.blue(chunk[index]),
            'found. Result sent to output.csv',
          );
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

export default simpleVendor;
