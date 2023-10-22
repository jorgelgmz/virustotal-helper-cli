import fs from 'fs/promises';
import path from 'path';
import axios from 'axios';
import chalk from 'chalk';

const wait = (ms) => new Promise((res) => setTimeout(res, ms));

const getSentinelOne = async (api) => {
  try {
    const hashes = (await fs.readFile(path.join(process.cwd(), 'hashes.txt'), 'utf-8')).split(/\n\r?/);
    await fs.appendFile(
      path.join(process.cwd(), 'output.csv'),
      `Name,Hash,Category,Engine Name,Engine Version,Result,Method,Engine Update\n`,
      'utf-8',
    );
    for (let hash of hashes) {
      try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'X-Apikey': api },
        });
        const scanners = await response.data.data.attributes.last_analysis_results;
        if (await scanners.SentinelOne) {
          await fs.appendFile(
            path.join(process.cwd(), 'output.csv'),
            `${response.data.data.attributes.names.toString().replaceAll(',', ';')},${hash}${scanners.SentinelOne.category},${
              scanners.SentinelOne.engine_name
            },${scanners.SentinelOne.engine_version},${scanners.SentinelOne.result},${scanners.SentinelOne.method},${
              scanners.SentinelOne.engine_update
            }\n`,
          );
          console.log('✅', chalk.bold.blue('Success:'), 'SentinelOne detection for', chalk.bold.blue(hash), 'found. Result sent to output.csv');
        } else {
          console.error('⛔️', chalk.bold.red('Error:'), 'SentinelOne not found');
        }
        await wait(500);
      } catch (err) {
        console.error('⛔️', chalk.bold.red('Error:'), 'Unable to reach VirusTotal with error message', err.message);
      }
    }
  } catch (err) {
    console.error('⛔️', chalk.bold.red('Error:'), 'Unable to read hashes.txt with error message', err.message);
  }
};

export default getSentinelOne;
