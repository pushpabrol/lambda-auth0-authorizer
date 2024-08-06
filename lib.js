require("dotenv").config({ silent: true });

const jwksClient = require("jwks-rsa");
const jwt = require("jsonwebtoken");
const util = require("util");

const getPolicyDocument = (effect, resource) => {
  const policyDocument = {
    Version: "2012-10-17",
    Statement: [
      {
        Action: "execute-api:Invoke",
        Effect: effect,
        Resource: resource,
      },
    ],
  };
  return policyDocument;
};

// extract and return the Bearer Token from the Lambda event parameters
const getToken = (params) => {
  if (!params.type || params.type !== "TOKEN") {
    throw new Error('Expected "event.type" parameter to have value "TOKEN"');
  }

  const tokenString = params.authorizationToken;
  if (!tokenString) {
    throw new Error('Expected "event.authorizationToken" parameter to be set');
  }

  const match = tokenString.match(/^Bearer (.*)$/);
  if (!match || match.length < 2) {
    throw new Error(
      `Invalid Authorization token - ${tokenString} does not match "Bearer .*"`
    );
  }
  return match[1];
};

const tokenConfigs = {
  default: {
    audience: process.env.AUDIENCE,
    issuer: process.env.TOKEN_ISSUER,
    jwksUri: process.env.JWKS_URI,
    publicKey: process.env.PUBLIC_KEY,
  },
  external_api_token: {
    audience: process.env.AUDIENCE,
    issuer: process.env.AUTH0_EXTERNAL_API_TOKEN_ISSUER,
    jwksUri: process.env.EXTERNAL_API_JWKS_URI,
    publicKey: process.env.EXTERNAL_API_JWT_PUBLIC_KEY,
  },
};

const clients = {
  default: jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: tokenConfigs.default.jwksUri,
  }),
  external_api_token: jwksClient({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: tokenConfigs.external_api_token.jwksUri,
  }),
};

module.exports.authenticate = async (params) => {
  console.log(params);
  const token = getToken(params);

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded || !decoded.header) {
    throw new Error("invalid token");
  }

  let tokenType = 'default';
  // Determine token type based on issuer or other criteria
  if (decoded.payload.iss === tokenConfigs.external_api_token.issuer) {
    tokenType = 'external_api_token';
  }

  const config = tokenConfigs[tokenType];
  const client = clients[tokenType];

  let signingKey;

  // If a kid was provided, this comes from Auth0. Get the public key from the authorization server
  if (decoded.header.kid) {
    const getSigningKey = util.promisify(client.getSigningKey);
    signingKey = await getSigningKey(decoded.header.kid).then(
      (key) => key.publicKey || key.rsaPublicKey
    );
  } else {
    signingKey = config.publicKey.replace(/\\n/g, "\n");
  }
  const jwtOptions = {
    audience: config.audience,
    issuer: config.issuer,
  };

  try {
    const verified = await jwt.verify(token, signingKey, jwtOptions);
    return {
      principalId: verified.sub,
      policyDocument: getPolicyDocument("Allow", params.methodArn),
      context: { scope: verified.scope },
    };
  } catch (error) {
    console.error('Token verification failed:', error);
    throw new Error('Invalid token');
  }
};