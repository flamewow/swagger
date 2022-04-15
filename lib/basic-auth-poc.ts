// @ts-nocheck - may need to be at the start of file

import * as auth from 'basic-auth';
import * as assert from 'assert';
import { timingSafeEqual } from 'crypto';

// Credits for the actual algorithm go to github/@Bruce17
// Thanks to github/@hraban for making me implement this
function safeCompare(userInput, secret) {
  const userInputLength = Buffer.byteLength(userInput);
  const secretLength = Buffer.byteLength(secret);

  const userInputBuffer = Buffer.alloc(userInputLength, 0, 'utf8');
  userInputBuffer.write(userInput);
  const secretBuffer = Buffer.alloc(userInputLength, 0, 'utf8');
  secretBuffer.write(secret);

  return !!(
    timingSafeEqual(userInputBuffer, secretBuffer) &
    (userInputLength === secretLength)
  );
}

function ensureFunction(option, defaultValue) {
  if (option == undefined)
    return function () {
      return defaultValue;
    };

  if (typeof option != 'function')
    return function () {
      return option;
    };

  return option;
}

export function buildMiddleware(options, isFastify = false) {
  const challenge =
    options.challenge != undefined ? !!options.challenge : false;
  const users = options.users || {};
  const authorizer = options.authorizer || staticUsersAuthorizer;
  const isAsync =
    options.authorizeAsync != undefined ? !!options.authorizeAsync : false;
  const getResponseBody = ensureFunction(options.unauthorizedResponse, '');
  const realm = ensureFunction(options.realm);

  assert(
    typeof users == 'object',
    'Expected an object for the basic auth users, found ' +
      typeof users +
      ' instead'
  );
  assert(
    typeof authorizer == 'function',
    'Expected a function for the basic auth authorizer, found ' +
      typeof authorizer +
      ' instead'
  );

  function staticUsersAuthorizer(username, password) {
    for (const i in users)
      if (safeCompare(username, i) & safeCompare(password, users[i]))
        return true;

    return false;
  }

  return function authMiddleware(req, res, next) {
    const authentication = auth(req);

    if (!authentication) return unauthorized();

    req.auth = {
      user: authentication.name,
      password: authentication.pass
    };

    if (isAsync)
      return authorizer(
        authentication.name,
        authentication.pass,
        authorizerCallback
      );
    else if (!authorizer(authentication.name, authentication.pass))
      return unauthorized();

    return next();

    function unauthorized() {
      //TODO: Allow response body to be JSON (maybe autodetect?)
      const response = getResponseBody(req);

      if (challenge) {
        let challengeString = 'Basic';
        const realmName = realm(req);

        if (realmName) challengeString += ' realm="' + realmName + '"';

        if (isFastify) {
          res.setHeader('WWW-Authenticate', challengeString);
        } else {
          res.set('WWW-Authenticate', challengeString);
        }
      }

      if (typeof response == 'string') {
        if (isFastify) {
          res.statusCode = 401;
          return res.end(response);
        } else {
          return res.status(401).send(response);
        }
      }

      if (isFastify) {
        res.statusCode = 401;
        return res.end(response);
      } else {
        return res.status(401).json(response);
      }
    }

    function authorizerCallback(err, approved) {
      assert.ifError(err);

      if (approved) return next();

      return unauthorized();
    }
  };
}
