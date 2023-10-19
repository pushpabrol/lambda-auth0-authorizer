const lib = require('./lib');
const Sentry = require("@sentry/serverless");

Sentry.AWSLambda.init({
  dsn: process.env.SENTRY_DSN,
  tracesSampleRate: 1.0,
});

let data;

module.exports.handler = Sentry.AWSLambda.wrapHandler(async (event, context) => {
  try {
    data = await lib.authenticate(event);
  }
  catch (err) {
      console.error(err);
      Sentry.captureException(err);
      return context.fail("Unauthorized");
  }
  return data;
});
