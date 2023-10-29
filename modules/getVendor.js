import fs from 'fs/promises';
import path from 'path';
import axios from 'axios';
import chalk from 'chalk';

const wait = (ms) => new Promise((res) => setTimeout(res, ms));

const getVendor = async (api, location, vendor) => {
  try {
    let hashes = (await fs.readFile(location, 'utf-8')).split(/\n\r?/);
    hashes = hashes.filter((hash) => hash !== '');
    await fs.appendFile(
      path.join(process.cwd(), 'output.csv'),
      `Name,Hash,Category,Engine Name,Engine Version,Result,Method,Engine Update\n`,
      'utf-8',
    );
    try {
      const requests = hashes.map(async (hash) => {
        return axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'X-Apikey': api },
        });
      });
      const responses = await Promise.all(requests);
      responses.forEach(async (response, index) => {
        const scanners = await response.data.data.attributes.last_analysis_results;
        if (await scanners[vendor]) {
          await fs.appendFile(
            path.join(process.cwd(), 'output.csv'),
            `${response.data.data.attributes.names.toString().replaceAll(',', ';')},${hashes[index]},${scanners[vendor].category},${
              scanners[vendor].engine_name
            },${scanners[vendor].engine_version},${scanners[vendor].result},${scanners[vendor].method},${scanners[vendor].engine_update}\n`,
          );
          console.log(
            '✅',
            chalk.bold.blue('Success:'),
            `${vendor} detection for`,
            chalk.bold.blue(hashes[index]),
            'found. Result sent to output.csv',
          );
        } else {
          console.error('⛔️', chalk.bold.red('Error:'), `${vendor} not found in VirusTotal`);
        }
        await wait(500);
      });
    } catch (err) {
      console.error('⛔️', chalk.bold.red('Error:'), 'Unable to reach VirusTotal with error message', err.message);
    }
  } catch (err) {
    console.error('⛔️', chalk.bold.red('Error:'), 'Unable to read the hashes file with error message', err.message);
  }
};

export default getVendor;
