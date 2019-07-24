# Auth0's AWS API Gateway Custom Authorizer for RS256 JWTs

For the original readme, please refer to [where this repo is forked from](https://github.com/auth0-samples/jwt-rsa-aws-custom-authorizer).


## Setup

1. Clone this repo
2. `npm install`
3. ready your [`.env`](https://github.com/rakroll/jwt-rsa-aws-custom-authorizer/blob/master/.env) and [event.json](https://github.com/rakroll/jwt-rsa-aws-custom-authorizer/blob/master/.event.json) files by look at their sample counterparts ([`.env.sample`](https://github.com/rakroll/jwt-rsa-aws-custom-authorizer/blob/master/.env./sample) & [event.json](https://github.com/rakroll/jwt-rsa-aws-custom-authorizer/blob/master/event.sample.json))
4. `npm test` to see if your `.env` works with your `event.json`
5. `npm bundle` and upload the resulting `custom-authorizer.zip` to your API Gateway


## What is `.env` here?
* `TOKEN_ISSUER`: The issuer of the token. `https://YOUR-TENANT.auth0.com/`
* `JWKS_URI`: This is the URL of the associated JWKS endpoint. `https://YOUR-TENANT.auth0.com/.well-known/jwks.json`
* `AUDIENCE`: This is the required audience of the token. The audience value is the same thing as your API **Identifier** for the specific API in your [APIs section]((https://manage.auth0.com/#/apis)).


## What is `event.json` here?

* `type`: `'TOKEN'`
* `authorizationToken`: It should have a value that resembles `'Bearer ACCESSTOKENHERE'`. The access token can be gotten inside your specific API's test tab in your [APIs section]((https://manage.auth0.com/#/apis)
* `methodArn`: string value of the specific [API Gateway's ARN](https://user-images.githubusercontent.com/14366908/61774859-bfbdde00-ae32-11e9-95af-47302649d98f.png).