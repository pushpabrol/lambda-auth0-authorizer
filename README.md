# AWS API Gateway Custom Authorizer for RS256 JWTs

An AWS API Gateway [Custom Authorizer](http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html) that authorizes API requests by requiring
that the OAuth2 [bearer token](https://tools.ietf.org/html/rfc6750) is a JWT that can be validated using the RS256 (asymmetric) algorithm with a public key that is obtained from a [JWKS](https://tools.ietf.org/html/rfc7517) endpoint.

## About

### What is AWS API Gateway?

API Gateway is an AWS service that allows for the definition, configuration and deployment of REST API interfaces.
These interfaces can connect to a number of back-end systems.
One popular use case is to provide an interface to AWS Lambda functions to deliver a so-called 'serverless' architecture.

### What are "Custom Authorizers"?

In February 2016 Amazon
[announced](https://aws.amazon.com/blogs/compute/introducing-custom-authorizers-in-amazon-api-gateway/)
a new feature for API Gateway -
[Custom Authorizers](http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html). This allows a Lambda function to be invoked prior to an API Gateway execution to perform custom authorization of the request, rather than using AWS's built-in authorization. This code can then be isolated to a single centralized Lambda function rather than replicated across every backend Lambda function.

### What does this Custom Authorizer do?

This package gives you the code for a custom authorizer that will, with a little configuration, perform authorization on AWS API Gateway requests via the following:

* It confirms that an OAuth2 bearer token has been passed via the `Authorization` header.
* It confirms that the token is a JWT that has been signed using the RS256 algorithm with a specific public key
* It obtains the public key by inspecting the configuration returned by a configured JWKS endpoint
* It also ensures that the JWT has the required Issuer (`iss` claim) and Audience (`aud` claim)

## Setup

Install Node Packages:

```bash
npm install
```

This is a prerequisite for deployment as AWS Lambda requires these files to be included in a bundle (a special ZIP file).

## Local testing

Configure the local environment with a `.env` file by copying the sample:

```bash
cp .env.sample .env
```

### Environment Variables

Modify the `.env`:
* `TOKEN_ISSUER`: The issuer of the token. If you're using Auth0 as the token issuer, this would be: `https://your-tenant.auth0.com/`
* `JWKS_URI`: This is the URL of the associated JWKS endpoint. If you are using Auth0 as the token issuer, this would be: `https://your-tenant.auth0.com/.well-known/jwks.json`
* `AUDIENCE`: This is the required audience of the token. If you are using Auth0 as the Authorization Server, the audience value is the same thing as your API **Identifier** for the specific API in your [APIs section]((https://manage.auth0.com/#/apis)).

You can test the custom authorizer locally. You just need to obtain a valid JWT access token to perform the test. If you're using Auth0, see [these instructions](https://auth0.com/docs/tokens/access-token#how-to-get-an-access-token) on how to obtain one.

With a valid token, now you just need to create a local `event.json` file that contains it. Start by copying the sample file:

```bash
cp event.json.sample event.json
```

Then replace the `ACCESS_TOKEN` text in that file with the JWT you obtained in the previous step.

Finally, perform the test:

```bash
npm test
```

This uses the [lambda-local](https://www.npmjs.com/package/lambda-local) package to test the authorizer with your token. A successful test run will look something like this:

```
> lambda-local --timeout 300 --lambdapath index.js --eventpath event.json

Logs
----
START RequestId: fe210d1c-12de-0bff-dd0a-c3ac3e959520
{ type: 'TOKEN',
    authorizationToken: 'Bearer eyJ0eXA...M2pdKi79742x4xtkLm6qNSdDYDEub37AI2h_86ifdIimY4dAOQ',
    methodArn: 'arn:aws:execute-api:us-east-1:1234567890:apiId/stage/method/resourcePath' }
END


Message
------
{
    "principalId": "user_id",
    "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Stmt1459758003000",
                "Effect": "Allow",
                "Action": [
                    "execute-api:Invoke"
                ],
                "Resource": [
                    "arn:aws:execute-api:*"
                ]
            }
        ]
    }
}
```

An `Action` of `Allow` means the authorizer would have allowed the associated API call to the API Gateway if it contained your token.

## Deployment

Now we're ready to deploy the custom authorizer to an AWS API Gateway.

### Create the lambda bundle

First we need to create a bundle file that we can upload to AWS:

```bash
npm run bundle
```

This will generate a local `custom-authorizer.zip` bundle (ZIP file) containing all the source, configuration and node modules an AWS Lambda needs.

### Create the IAM role

Before we can create the Lambda function in AWS that will be used as the custom authorizer, we need to make sure we have an IAM role that has permissions to invoke the Lambda function.

Before we create the role, we need to make sure we have an IAM policy  with the right permissions, which essentially allow for invoking Lambda functions. The policy JSON needs to look like this:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:InvokeFunction"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```

Your AWS account should have an existing policy called `AWSLambdaRole` in the [Policies](https://console.aws.amazon.com/iam/home#/policies) list that has these permissions, so you don't have to create a new policy if you don't want to.

Now in the AWS Console, go to your [IAM Roles](https://console.aws.amazon.com/iam/home#/roles) list and create new role:

1. Click **Create new role**
2. Under the **AWS Service Role** group, click the **Select** button for the `AWS Lambda` role type
3. In the **Attach Policy** step, select the `AWSLambdaRole` policy
4. Provide the role a name. Eg: `Custom-Authorizer-Role`
5. Select your new role in the role list
6. Click the **Trust relationships** tab and click the **Edit trust relationship** button
7. Update the policy document so it has this JSON:

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": [
              "apigateway.amazonaws.com",
              "lambda.amazonaws.com"
            ]
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
    ```

8. Make note of the **Role ARN** value, which will be used in a later step

### Create the lambda function

Now we can finally create the lamda function itself in AWS. Start by going to [create a new blank function](https://console.aws.amazon.com/lambda/home#/create?step=2), then click **Next**. Your new function will have the following configuration:

* Name: `jwtRsaCustomAuthorizer`
* Description: `JWT RSA Custom Authorizer`
* Runtime: `Node.js 8.10`
* _Lambda function code_
    * Code entry type: `Update a .ZIP file`
    * Function package: (upload the `custom-authorizer.zip` file created earlier)
    * Environment variables: (create variables with the same _Key_ and _Value_ as the list in the [Environment Variables](#environment-variables) section above)
* _Lambda function handler and role_
    * Handler: `index.handler` (default)
    * Role: `Choose an existing role`
    * Existing role: `Custom-Authorizer-Role` (same role created earlier)
* _Advanced Settings_
    * Timeout: `30` seconds

Click **Next** and then **Create function** to create the lambda function.

### Test the lambda function in AWS

1. Make sure your new lamdba function is open in the console, and from the **Actions** menu select `Configure test event`.

2. Copy the contents of your `event.json` file into the **Input test event** JSON.

3. Click **Save and test** to run the lambda.

You should see similar output to what you observed when [testing the lambda locally](#local-testing).

### Configure the Custom Authorizer in the API Gateway

1. In the [AWS API Gateway console](https://console.aws.amazon.com/apigateway/home) open an existing API, or optionally create a **New API**.

2. In the left panel, under your API name, click **Authorizers**.

3. Click **Create** > **Custom Authorizer**

4. Use the following values in the **New Custom Authorizer** form:
   * Lambda region: (same as lambda function created above)
   * Lambda function: `jwtRsaCustomAuthorizer`
   * Authorizer name: `jwt-rsa-custom-authorizer`
   * Execution role: (**Role ARN** from the [Create the IAM role](#create-the-iam-role) section)
   * Token validation expression: `^Bearer [-0-9a-zA-Z\._]*$`
   * Result TTL in seconds: `3600`

5. Click **Create**

### Test the Custom Authorizer in the API Gateway

You can then test the new custom authorizer by providing an **Identity Token** and clicking **Test**. The ACCESS_TOKEN is the same format we used in `event.json` above:

```
Bearer ACCESS_TOKEN
```

A successful test will look something like:

```
Latency: 2270 ms
Principal Id: oauth|1234567890
Policy
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1459758003000",
            "Effect": "Allow",
            "Action": [
                "execute-api:Invoke"
            ],
            "Resource": [
                "arn:aws:execute-api:*"
            ]
        }
    ]
}
```

### Configure API Gateway Resources to use the Custom Authorizer

1. In the left panel, under your API name, click **Resources**.

2. Under the Resource tree, select a specific resource and one of its Methods (eg. `GET`)

3. Select **Method Request**

4. Under the **Settings** section, click the pencil to the right of the **Authorization** and choose the `jwt-rsa-custom-authorizer` Custom Authorizer. Click the checkbox to the right of the drop down to save.

5. Make sure the **API Key Required** field is set to `false`

### Deploy the API Gateway

You need to Deploy the API to make the changes public.

1. Select the **Action** menu and choose **Deploy API**

2. When prompted for a stage, select or create a new stage (eg. `dev`).

3. In the stage, make note of the **Invoke URL**

### Test your API Gateway endpoint remotely

In the examples below:
* `INVOKE_URL` is the **Invoke URL** from the [Deploy the API Gateway](#deploy-the-api-gateway) section above
* `ACCESS_TOKEN` is the token in the `event.json` file
* `/your/resource` is the resource you secured in AWS API Gateway

#### With Postman

You can use Postman to test the REST API

* Method: (matching the Method in API Gateway, eg. `GET`)
* URL: `INVOKE_URL/your/resource`
* Headers tab: Add an `Authorization` header with the value `Bearer ACCESS_TOKEN`

#### With curl from the command line

```
curl -i "INVOKE_URL/your/resource" \
  -X GET \
  -H 'Authorization: Bearer ACCESS_TOKEN'
```

The above command is performed using the `GET` method.

#### In (modern) browsers console with fetch

```
fetch( 'INVOKE_URL/your/resource', { method: 'GET', headers: { Authorization : 'Bearer ACCESS_TOKEN' }}).then(response => { console.log( response );});
```


---

## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, amongst others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
