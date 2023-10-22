import fs from 'fs/promises';
import path from 'path';
import axios from 'axios';
import chalk from 'chalk';

const wait = (ms) => new Promise((res) => setTimeout(res, ms));

const getAllVendors = async (api) => {
  try {
    const hashes = (await fs.readFile(path.join(process.cwd(), 'hashes.txt'), 'utf-8')).split(/\n\r?/);
    await fs.appendFile(
      path.join(process.cwd(), 'output.csv'),
      `Name,Vendor,Category,Engine Name,Engine Version,Result,Method,Engine Update\n`,
      'utf-8',
    );
    for (let hash of hashes) {
      try {
        const response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'X-Apikey': api },
        });
        const vendors = await response.data.data.attributes.last_analysis_results;
        for (let vendor of Object.entries(vendors)) {
          await fs.appendFile(
            path.join(process.cwd(), 'output.csv'),
            `${response.data.data.attributes.names.toString().replaceAll(',', ';')},${vendor[0]},${vendor[1].category},${vendor[1].engine_name},${
              vendor[1].engine_version
            },${vendor[1].result},${vendor[1].method},${vendor[1].engine_update}\n`,
          );
          console.log('✅', chalk.bold.blue('Success:'), 'Result found for', chalk.bold.blue(vendor[0]), 'and sent to output.csv');
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

export default getAllVendors;
