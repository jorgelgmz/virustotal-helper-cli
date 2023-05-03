import fs from 'fs/promises';
import path from 'path';
import axios from 'axios';
import chalk from 'chalk';

const wait = (ms) => new Promise((res) => setTimeout(res, ms));

const getHashes = async (api) => {
  const hashes = (await fs.readFile(path.join(process.cwd(), 'hashes.txt'), 'utf-8')).split(/\n\r?/);
  fs.appendFile(path.join(process.cwd(), 'output.csv'), `Name,File Type,SHA256,SHA1,MD5,SSDEEP\n`, 'utf-8');
  for (let hash of hashes) {
    try {
      let response = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
        headers: { 'X-Apikey': api },
      });
      await fs.appendFile(
        path.join(process.cwd(), 'output.csv'),
        `${response.data.data.attributes.names.toString().replaceAll(',', ';')},${response.data.data.attributes.type_description},${
          response.data.data.attributes.sha256
        },${response.data.data.attributes.sha1},${response.data.data.attributes.md5},${response.data.data.attributes.ssdeep}\n`,
        'utf8',
      );
      await wait(500);
      console.log(`${chalk.blue.bold('Success:')} Match found for ${chalk.blue.bold(hash)}. Result sent to output.csv`);
    } catch (err) {
      console.error(`Unable to get hash value with error message: ${chalk.red.bold(err.message)}`);
    }
  }
};

export default getHashes;
