const express = require('express');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const useragent = require('express-useragent');
const logger = require('morgan');
const jwksClient = require('jwks-rsa');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');
const { isoBase64URL } = require('@simplewebauthn/server/helpers');
const { connect, Users, Credentials, RequestLogs, RandBytes, Nonce, VerificationToken } = require('./db.js');

const app = express();
const port = 4444;

// middleware
app.use(express.json());
app.use(cookieParser());
app.use(useragent.express());
app.set('view engine', 'ejs');
app.use(logger("short"));
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'), // Replace with your own session secret
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // In production, set to true and use HTTPS
}));

const RP_NAME = 'RP';
const IDP_HOST = process.env.IDP_HOST === 'idp' ? 'idp' : 'localhost';
const MODE = process.env.MODE || 'dev';

app.use((req, res, next) => {
  process.env.HOSTNAME = req.hostname;
  const protocol = 'https';
  process.env.ORIGIN = `${protocol}://${req.headers.host}`;
  process.env.RP_NAME = RP_NAME;
  return next();
});

const clientID = 'client';
const redirectUri = process.env.REDIRECT_URI;
const idpUrl = 'http://idp:4445';

const client = jwksClient({
  jwksUri: `${idpUrl}/.well-known/jwks.json`
});

const users = {};
const verificationTokens = {};

function getKey(header, callback){
  client.getSigningKey(header.kid, function(err, key) {
    var signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

(async () => {
  // Connect to MongoDB
  await connect();
})();

// index page
app.get('/', (req, res) => {
  res.render('index', { username: req.session.username });
});

// send authentication request to IdP
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  let url;
  if (MODE === 'dev') {
    url = new URL(`http://localhost:4445/authorize`);
  } else {
    url = new URL(`http://${IDP_HOST}:4445/authorize`);
  }
  url.searchParams.set('response_type', 'id_token');
  url.searchParams.set('client_id', clientID);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('scope', 'openid');
  url.searchParams.set('nonce', nonce);
  
  res.redirect(url.toString());
});

// callback endpoint
app.get('/callback', async (req, res) => {
  res.render('callback');
});

// process ID token and send verification email
app.post('/callback', async (req, res) => {
  try {
    const { idToken } = req.body;
    console.log("idToken:", idToken);
    if (!idToken) {
      return res.status(400).send('Missing ID token');
    }

    // Verify ID token
    const decoded = await new Promise((resolve, reject) => {
      jwt.verify(idToken, getKey, { algorithms: ['RS256'] }, (err, decodedToken) => {
        if (err) {
          reject(err);
        } else {
          resolve(decodedToken);
        }
      });
    });

    // generate verification URL
    const verificationToken = crypto.randomBytes(16).toString('hex');
    // const verificationUrl = `http://localhost:${port}/callback?token=${verificationToken}`;

    // save verification token
    VerificationToken.create({
      sub: decoded.sub,
      username: decoded.name,
      token: verificationToken,
    });

    // send verification email (not implemented)

    // send verification token
    res.json({ message: 'Verification email sent.', verificationToken: verificationToken });

  } catch (error) {
    res.status(400).send(`Invalid ID token: ${error.message}`);
  }
});

app.get('/logout', async(req, res) => {
  // delete all random bytes
  await RandBytes.deleteBySub(req.session.username);
  // destroy the session
  req.session.destroy();

  res.redirect('/');
});

// FIDO related functions
/**
 * Get the expected origin that the user agent is claiming to be at. If the
 * requester is Android, construct an expected `origin` parameter.
 * @param { string } userAgent A user agent string used to check if it's a web browser.
 * @returns A string that indicates an expected origin.
 */
function getOrigin(userAgent) {
  let origin = process.env.ORIGIN;
  
  const appRe = /^[a-zA-z0-9_.]+/;
  const match = userAgent.match(appRe);
  if (match) {
    // Check if UserAgent comes from a supported Android app.
    if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
      // `process.env.ANDROID_PACKAGENAME` is expected to have a comma separated package names.
      const package_names = process.env.ANDROID_PACKAGENAME.split(",").map(name => name.trim());
      // `process.env.ANDROID_SHA256HASH` is expected to have a comma separated hash values.
      const hashes = process.env.ANDROID_SHA256HASH.split(",").map(hash => hash.trim());
      const appName = match[0];
      // Find and construct the expected origin string.
      for (let i = 0; i < package_names.length; i++) {
        if (appName === package_names[i]) {
          // We recognize this app, so use the corresponding hash.
          const octArray = hashes[i].split(':').map((h) =>
            parseInt(h, 16),
          );
          const androidHash = isoBase64URL.fromBuffer(octArray);
          origin = `android:apk-key-hash:${androidHash}`;
          break;
        }
      }
    }
  }
  
  return origin;
}  

/**
* Checks CSRF protection using custom header `X-Requested-With`
* If the session doesn't contain `signed-in`, consider the user is not authenticated.
**/
async function sessionCheck(req, res, next) {
  if (!req.session.username) {
    return res.status(401).json({ error: 'not accepted yet' });
  }
  const user = await Users.findByUsername(req.session.username);
  if (!user) {
    return res.status(401).json({ error: 'user not found.' });    
  }
  res.locals.user = user;
  next();
};

// FIDO related endpoints
// Get options for creating new credentials
app.post('/auth/registerRequest', async (req, res) => {
  const { verificationToken } = req.body;
  if (!verificationToken) {
    return res.status(400).send('Missing verification token');
  }

  // vefify verification token
  const token = await VerificationToken.findByToken(verificationToken);
  if (!token) {
    return res.status(400).send('Invalid verification token');
  }

  // Check if the user already exists.
  let user = await Users.findBySub(token.sub);
  if (!user) {
    // Create a new user.
    user = {
      id: isoBase64URL.fromBuffer(crypto.randomBytes(32)),
      username: token.username,
      sub: token.sub,
      registered: false, // not registered yet
    };
    await Users.create(user);
  }

  req.session.username = user.sub;

  // Create `excludeCredentials` from a list of stored credentials.
  const excludeCredentials = [];
  const credentials = await Credentials.findByUserId(user.sub);
  for (const cred of credentials) {
      excludeCredentials.push({
          id: isoBase64URL.toBuffer(user.sub),
          type: 'public-key',
          transports: cred.transports,
      });
  }

  const authenticatorSelection = {
      authenticatorAttachment: 'platform',
      requireResidentKey: true

  }
  const attestationType = 'none';

  // Use SimpleWebAuthn's handy function to create registration options.
  const options = await generateRegistrationOptions({
      rpName: process.env.RP_NAME,
      rpID: process.env.HOSTNAME,
      userID: user.sub,
      userName: user.username,
      userDisplayName: user.username,
      // Prompt users for additional information about the authenticator.
      attestationType,
      // Prevent users from re-registering existing authenticators
      excludeCredentials,
      authenticatorSelection,
  });
  
  req.session.challenge = options.challenge;
  console.log("options:", options);
  return res.json(options);
});

// Verify the registration response.
app.post('/auth/registerResponse', sessionCheck, async (req, res) => {
  // Set expected values.
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;
  const credential = req.body;

  try {
      // Use SimpleWebAuthn's handy function to verify the registration request.
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin,
        expectedRPID,
        requireUserVerification: false,
      });
  
      const { verified, registrationInfo } = verification;
  
      // If the verification failed, throw.
      if (!verified) {
        throw new Error('User verification failed.');
      }
  
      const { credentialPublicKey, credentialID } = registrationInfo;
  
      // Base64URL encode ArrayBuffers.
      const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);
      const base64CredentialID = isoBase64URL.fromBuffer(credentialID);
  
      const { user } = res.locals;
      
      // Store the registration result.
      await Credentials.create({
        id: base64CredentialID,
        publicKey: base64PublicKey,
        name: req.useragent.platform,
        transports: credential.response.transports || [],
        registered: (new Date()).getTime(),
        last_used: null,
        user_id: user.id,
      });

      // Update the user's registration status.
      user.registered = true;
      await Users.update(user);

      // Delete the challenge from the session.
      delete req.session.challenge;
  
      // Respond with the user information.
      return res.json(user);
  } catch (e) {
      delete req.session.challenge;
  
      console.error(e);
      return res.status(400).send({ error: e.message });
  }
});

// Start authenticating the user.
app.post('/auth/signinRequest', async (req, res) => {
  try {
      const { idToken } = req.body;
      if (!idToken) {
        return res.status(400).send('Missing ID token');
      }
      // verify ID token
      const claims = await new Promise((resolve, reject) => {
        jwt.verify(idToken, getKey, { algorithms: ['RS256'] }, (err, decodedToken) => {
          if (err) {
            reject(err);
          } else {
            resolve(decodedToken);
          }
        });
      });
      console.log("claims:", claims);

      // Check user's registration status.
      const user = await Users.findBySub(claims.sub);
      console.log("user:", user);
      if (!user) {
          throw new Error('User not found.');
      }
      if (!user.registered) {
          throw new Error('User not registered.');
      }

      // Use SimpleWebAuthn's handy function to create a new authentication request.
      const options = await generateAuthenticationOptions({
          rpID: process.env.HOSTNAME,
          allowCredentials: [],
      });
  
      // Keep the challenge value in a session.
      req.session.challenge = options.challenge;

      return res.json(options)
  } catch (e) {
      console.error(e);
  
      return res.status(400).json({ error: e.message });
  }
});

// Verify the authentication request.
app.post('/auth/signinResponse', async (req, res) => {
  // Set expected values.
  const credential = req.body.credential;
  const expectedChallenge = req.session.challenge;
  const expectedOrigin = getOrigin(req.get('User-Agent'));
  const expectedRPID = process.env.HOSTNAME;

  try {

      // Find the matching credential from the credential ID
      const cred = await Credentials.findById(credential.id);
      if (!cred) {
          throw new Error('Matching credential not found on the server. Try signing in with a password.');
      }
  
      // Find the matching user from the user ID contained in the credential.
      const user = await Users.findById(cred.user_id);
      if (!user) {
          throw new Error('User not found.');
      }
  
      // Decode ArrayBuffers and construct an authenticator object.
      const authenticator = {
          credentialPublicKey: isoBase64URL.toBuffer(cred.publicKey),
          credentialID: isoBase64URL.toBuffer(cred.id),
          transports: cred.transports,
      };
  
      // Use SimpleWebAuthn's handy function to verify the authentication request.
      const verification = await verifyAuthenticationResponse({
          response: credential,
          expectedChallenge,
          expectedOrigin,
          expectedRPID,
          authenticator,
          requireUserVerification: false,
      });
  
      const { verified, authenticationInfo } = verification;
  
      // If the authentication failed, throw.
      if (!verified) {
          throw new Error('User verification failed.');
      }
  
      // Update the last used timestamp.
      cred.last_used = (new Date()).getTime();
      await Credentials.update(cred);
  
      // Delete the challenge from the session.
      delete req.session.challenge;

      const { idToken } = req.body;
      if (!idToken) {
        return res.status(400).send('Missing ID token');
      }
      // verify ID token
      const claims = await new Promise((resolve, reject) => {
        jwt.verify(idToken, getKey, { algorithms: ['RS256'] }, (err, decodedToken) => {
          if (err) {
            reject(err);
          } else {
            resolve(decodedToken);
          }
        });
      });
      console.log("claims:", claims);

      // Save IP address and User Agent
      const remoteAddress = req.socket.remoteAddress;
      const sourceIp = remoteAddress.split(":").pop();
      const userAgent = req.headers['user-agent'];
      console.log(`IP: ${sourceIp}`);
      console.log(`User Agent: ${userAgent}`);

      await RequestLogs.create({
        sub: claims.sub,
        sourceIp: sourceIp,
        userAgent: userAgent,
      });

      // Generate random bytes
      const randBytes = crypto.randomBytes(16).toString('hex');

      // Save random bytes
      await RandBytes.create({
        sub: claims.sub,
        randBytes: randBytes,
      });
      
      // Start a new session.
      req.session.username = claims.sub;
      req.session['signed-in'] = 'yes';
  
      return res.json({
        user: user,
        randBytes: randBytes,
      });
  } catch (e) {
      delete req.session.challenge;
  
      console.error(e);
      return res.status(400).json({ error: e.message });
  }
});

// after sign in request
app.post('/after/signin', async(req, res) => {
  try {
    if (!req.session.username) {
      return res.status(400).json({ error: 'Please sign in.' });
    }

    if (!req.body.hash) {
      return res.status(400).json({ error: 'Missing hash.' });
    }
    
    const hash = req.body.hash;

    // get nonce
    const nonceArray = await Nonce.findBySub(req.session.username);
    const randBytesArray = await RandBytes.findBySub(req.session.username);
    console.log("nonceArray:", nonceArray);
    console.log("randBytesArray:", randBytesArray);


    // verify hash
    let hashResult = false;
    for (let i = 0; i < randBytesArray.length; i++) {
      for (let j = 0; j < nonceArray.length; j++) {
        const expectedHash = crypto.createHash('sha256').update(randBytesArray[i].randBytes+nonceArray[j].nonce).digest('hex');
        console.log("hash:", hash);
        console.log("expectedHash:", expectedHash);
        if (expectedHash === hash) {
          hashResult = true;
        }
      }
    }

    // verify sourceIp and userAgent
    let sourceResult = false;
    const remoteAddress = req.socket.remoteAddress;
    const sourceIp = remoteAddress.split(":").pop();
    const userAgent = req.headers['user-agent'];
    console.log(`IP: ${sourceIp}`);
    console.log(`User Agent: ${userAgent}`);
  
    const logs = await RequestLogs.findByIPAndUA(sourceIp, userAgent);
    console.log("logs:", logs);
    if (logs.length > 0) {
      sourceResult = true;
    }

    if (hashResult && sourceResult) {
      return res.json({ verified: true });
    }

    return res.json({ verified: false });

  } catch(e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
})

// signup without FIDO
app.post('/auth/normal/signup', async (req, res) => {
  try {
      const { idToken } = req.body;
      if (!idToken) {
        return res.status(400).send('Missing ID token');
      }
      // verify ID token
      const claims = await new Promise((resolve, reject) => {
        jwt.verify(idToken, getKey, { algorithms: ['RS256'] }, (err, decodedToken) => {
          if (err) {
            reject(err);
          } else {
            resolve(decodedToken);
          }
        });
      });
      console.log("claims:", claims);

      // Check if the user already exists.
      let user = await Users.findBySub(claims.sub);
      if (user) {
          // User already exists.
          return res.status(400).json({ error: 'User already exists.' });
      }

      // Create a new user.
      user = {
          id: isoBase64URL.fromBuffer(crypto.randomBytes(32)),
          username: claims.name,
          sub: claims.sub,
          registered: true,
      };
      await Users.create(user);

      req.session.username = claims.sub;

      return res.json(user);

  } catch(e) {
      console.error(e);
      return res.status(400).json({ error: e.message });
  }
});

// signin without FIDO
app.post('/auth/normal/signin', async (req, res) => {
  try {
      const { idToken } = req.body;
      if (!idToken) {
        return res.status(400).send('Missing ID token');
      }
      // verify ID token
      const claims = await new Promise((resolve, reject) => {
        jwt.verify(idToken, getKey, { algorithms: ['RS256'] }, (err, decodedToken) => {
          if (err) {
            reject(err);
          } else {
            resolve(decodedToken);
          }
        });
      });
      console.log("claims:", claims);

      const user = await Users.findBySub(claims.sub);
      if (!user) {
          throw new Error('User not found.');
      }

      // Start a new session.
      req.session.username = user.sub;
      req.session['signed-in'] = 'yes';
  
      return res.json(user);

  } catch (e) {
      console.error(e);
      return res.status(400).json({ error: e.message });
  }
});

// after sign in request without FIDO
app.post('/after/normal/signin', async(req, res) => {
  try {
    if (!req.session.username) {
      return res.status(400).json({ error: 'Please sign in.' });
    }

    res.json({ verified: true });
  }
  catch(e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
})

// get nonce 
app.post('/nonce', async (req, res) => {
  try {
    if (!req.session.username) {
      return res.status(400).json({ error: 'Please sign in.' });
    }
    
    const nonce = crypto.randomBytes(16).toString('hex');
    await Nonce.create({
      sub: req.session.username,
      nonce: nonce,
    });
    return res.json({ nonce: nonce });
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
});

const httpsOptions = {
  key: fs.readFileSync('./certs/key.pem'),
  cert: fs.readFileSync('./certs/server.crt')
};

https.createServer(httpsOptions, app).listen(port, () => {
  console.log(`RP is running at http://localhost:${port}`);
});