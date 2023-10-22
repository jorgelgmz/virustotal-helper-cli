import inquirer from 'inquirer';
import getHashes from './modules/getHashes.js';
import getAllVendors from './modules/getAllVendors.js';
import getSentinelOne from './modules/getSentinelOne.js';
import getCrowdStrike from './modules/getCrowdStrike.js';
import getMicrosoft from './modules/getMicrosoft.js';
import getVendor from './modules/getVendor.js';

(async () => {
  const questions = await inquirer.prompt([
    {
      name: 'api',
      message: 'Please enter your API Key:',
      type: 'password',
      mask: true,
      validate: (questions) => {
        return questions.length > 1;
      },
    },
    {
      name: 'operation',
      message: 'What would you like to do?',
      type: 'checkbox',
      choices: [
        {
          name: 'Get all hashes',
        },
        {
          name: 'Check all vendors',
        },
        {
          name: 'Check SentinelOne',
        },
        {
          name: 'Check CrowdStrike',
        },
        {
          name: 'Check Microsoft',
        },
        {
          name: 'Check a specific vendor',
        },
      ],
      validate(questions) {
        if (questions.length < 1) {
          return 'You must choose one operation.';
        } else if (questions.length > 1) {
          return 'You must choose one operation.';
        }

        return true;
      },
    },
  ]);
  if (questions.operation.toString() === 'Check a specific vendor') {
    const vendorQuestion = await inquirer.prompt([
      {
        type: 'input',
        name: 'vendor',
        message: 'What vendor would you like to check?',
        default() {
          return 'McAfee';
        },
      },
    ]);
    getOperation(questions.api.toString(), questions.operation.toString(), vendorQuestion.vendor.toString());
  } else {
    getOperation(questions.api.toString(), questions.operation.toString());
  }
})();

const getOperation = async (api, operation, vendor) => {
  if (operation === 'Get all hashes') {
    await getHashes(api);
  } else if (operation === 'Check all vendors') {
    await getAllVendors(api);
  } else if (operation === 'Check SentinelOne') {
    await getSentinelOne(api);
  } else if (operation === 'Check CrowdStrike') {
    await getCrowdStrike(api);
  } else if (operation === 'Check Microsoft') {
    await getMicrosoft(api);
  } else if (operation === 'Check a specific vendor') {
    await getVendor(api, vendor);
  }
};
