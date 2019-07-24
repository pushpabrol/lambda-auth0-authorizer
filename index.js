const lib = require('./lib');
let data;

// Lambda function to handle token authentication
module.exports.handler = async (event) => {
  try {
    data = await lib.authenticate(event);
  }
  catch (err) {
    console.log(err);
    return `Unauthorized: ${err.message}`;
  }
  return data;
};
