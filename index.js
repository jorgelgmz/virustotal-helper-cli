import inquirer from 'inquirer';
import getHashes from './modules/getHashes.js';
import getSentinelOne from './modules/getSentinelOne.js';

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
          name: 'Get all hashes from input',
        },
        {
          name: 'Check SentinelOne for input',
        },
      ],
      validate(questions) {
        if (questions.length < 1) {
          return 'You must choose at least one operation.';
        }

        return true;
      },
    },
  ]);
  getOperation(questions.api.toString(), questions.operation.toString());
})();

const getOperation = async (api, operation) => {
  if (operation === 'Get all hashes from input') {
    await getHashes(api);
  } else if (operation === 'Check SentinelOne for input') {
    await getSentinelOne(api);
  }
};
