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

const getHashes = async (api, location) => {
  try {
    let hashes = (await fs.readFile(location, 'utf-8')).split(/\n\r?/);
    hashes = hashes.filter((hash) => hash !== '');
    hashes = hashes.map((hash) => hash.trim());
    fs.appendFile(path.join(process.cwd(), 'output.csv'), `Name,File Type,SHA256,SHA1,MD5,SSDEEP\n`, 'utf-8');
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
          await fs.appendFile(
            path.join(process.cwd(), 'output.csv'),
            `${response.data.data.attributes.names.toString().replaceAll(',', ';')},${response.data.data.attributes.type_description},${
              response.data.data.attributes.sha256
            },${response.data.data.attributes.sha1},${response.data.data.attributes.md5},${response.data.data.attributes.ssdeep}\n`,
            'utf8',
          );
          await wait(500);
          console.log('✅', `${chalk.blue.bold('Success:')} Match found for ${chalk.blue.bold(chunk[index])}. Result sent to output.csv`);
        });
      }
    } catch (err) {
      console.error('⛔️', `Unable to get hash value with error message: ${chalk.red.bold(err.message)}`);
    }
  } catch (err) {
    console.error('⛔️', chalk.bold.red('Error:'), 'Unable to read the hashes file with error message', err.message);
  }
};

export default getHashes;
