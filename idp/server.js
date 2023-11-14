const express = require('express');
const crypto = require('crypto');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const port = 4445;

const secret = crypto.randomBytes(32).toString('hex');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: secret,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } 
}));

const clients = {
  'client': {
    secret: 'secret',
    redirectUris: ['http://localhost:4444/callback'],
  },
};

const users = {};
const codes = {};

// add guest user
async function addInitialUser() {
  const userId = 'guest';
  const password = 'guest';
  const hashedPassword = await bcrypt.hash(password, 10);
  users[userId] = { userId, password: hashedPassword };
}

addInitialUser();

// generate JWK
const privateKey = fs.readFileSync('./keys/private_key.pem', 'utf8');
const kid = '1b4cae83f17f2a89c4a775a1f88f6aed9e04196fe0e3fb78b4b9cc47a6c0dcf1';

// JWKs endpoint
app.get('/.well-known/jwks.json', (req, res) => {
  const jwk = {
    "kty": "RSA",
    "n": "lU22Nv1E7tBwGzdDZ8zh11eUa0521sdsjR5CMoGHLZZv4qwkRXoar1hTO8t6kCGGNipcTTvEd1ESrphYLX_0UyFhE5XgklPb1KW9X3X0x79ydkHDaj1aZho2LtGYrJPkD0xM7Hk-ZlyyEiW6SHquYHMGNdpotyAhx-HfJ0Dv-zN8YMjF5TRqyCFACJSKgvf8pab0D6CrSpFtlmZI1DEgOh9hsAezRvSZW39X4FQK2M40ueIpfP_5len4JVLSsLLdzIQlMu6y59LAPVYSUG6umRO82jDlOntajtXe7O2r8oxzcrQVFSDRuOnQXAJk8BacgBBDPjHIZWyofkIzustp6w",
    "e": "AQAB",
    "alg": "RS256",
    "kid": "1b4cae83f17f2a89c4a775a1f88f6aed9e04196fe0e3fb78b4b9cc47a6c0dcf1",
    "use": "sig"
  };
  res.json({ keys: [jwk] }); // 上で生成した JWK を使用
});

// user registration form
app.get('/register', (req, res) => {
    res.send(`
      <form method="POST" action="/register">
        <label>User ID: <input type="text" name="userId" required /></label><br>
        <label>Password: <input type="password" name="password" required /></label><br>
        <input type="submit" value="Register" />
      </form>
    `);
});

// user registration
app.post('/register', async (req, res) => {
    const { userId, password } = req.body;
    
    if (users[userId]) {
      return res.status(400).send('User ID is already taken');
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);
    users[userId] = { userId, password: hashedPassword };
    
    res.send('Registration successful!');
});

// authorization endpoint
app.get('/authorize', (req, res) => {
  const { response_type, client_id, redirect_uri, state, scope } = req.query;
  
  const client = clients[client_id];
  if (!client || (response_type !== 'code' && response_type !== 'id_token') || !redirect_uri || !state || !scope) {
    return res.status(400).send('Invalid request');
  }

  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send('Invalid redirect_uri');
  }

  req.session.authDetails = { response_type, client_id, redirect_uri, state, scope };
  res.redirect('/login');
});

// login form
app.get('/login', (req, res) => {
    if (!req.session.authDetails) {
        return res.status(400).send('No auth details in session. Start over.');
    }

    res.send(`
        <form method="POST" action="/login">
            <label>User ID: <input type="text" name="userId" required /></label><br>
            <label>Password: <input type="password" name="password" required /></label><br>
            <input type="submit" value="Login" />
        </form>
    `);
});

// login
app.post('/login', async (req, res) => {
    const { userId, password } = req.body;
    
    if (!req.session.authDetails) {
      return res.status(400).send('No auth details in session. Start over.');
    }
    
    const user = users[userId];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).send('Invalid User ID or Password');
    }
    
    req.session.userId = userId; // Store user ID in session
    res.redirect('/consent'); // Redirect to the consent screen after successful login
});

// consent form
app.get('/consent', (req, res) => {
    if (!req.session.userId) {
      return res.status(400).send('Not logged in. <a href="/login">Login here</a>');
    }
  
    res.send(`
      <form method="POST" action="/consent">
        <p>Do you consent to share your information with the client?</p>
        <input type="submit" value="Yes" name="consent" />
        <input type="submit" value="No" name="consent" />
      </form>
    `);
});

// consent
app.post('/consent', (req, res) => {
    if (req.body.consent !== 'Yes') {
      return res.status(400).send('User denied the consent');
    }
    
    const authDetails = req.session.authDetails;
    if (!authDetails) {
      return res.status(400).send('No auth details in session. Start over.');
    }

    if (authDetails.response_type === 'id_token') {
      // Generate ID token and redirect to client with the token
      const now = Math.floor(Date.now() / 1000);
    
      const payload = {
        iss: 'http://localhost:4445', // The issuer of the token (your IdP)
        sub: req.session.userId, // The subject of the token (the user id)
        aud: authDetails.client_id, // The audience of the token (the client id)
        exp: now + 3600, // The expiration time of the token (1 hour from now)
        iat: now, // The issued at time of the token (now)
        auth_time: now, // The time the user was authenticated
        nonce: authDetails.nonce, // The nonce value received from the authentication request
      };

      const idToken = jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: kid });
  
      const { redirect_uri, state } = req.session.authDetails;
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.hash = `id_token=${idToken}&state=${state}`;
      
      res.redirect(redirectUrl.toString());

    } else if (authDetails.response_type === 'code') {
      const code = uuidv4();
      codes[code] = { ...req.session.authDetails, userId: req.session.userId };
      
      const { redirect_uri, state } = req.session.authDetails;
      const redirectUrl = new URL(redirect_uri);
      redirectUrl.searchParams.set('code', code);
      redirectUrl.searchParams.set('state', state);
      
      res.redirect(redirectUrl.toString());

    } else {
      res.status(400).send('Invalid response_type');
    }
});

// token endpoint
app.post('/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;
  
  const client = clients[client_id];
  if (!client || client.secret !== client_secret || grant_type !== 'authorization_code' || !code || !redirect_uri) {
    return res.status(400).send('Invalid request');
  }

  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).send('Invalid redirect_uri');
  }

  const authDetails = codes[code];
  if (!authDetails || authDetails.client_id !== client_id || authDetails.redirect_uri !== redirect_uri) {
    return res.status(400).send('Invalid code');
  }

  delete codes[code];

  const now = Math.floor(Date.now() / 1000);
    
  const payload = {
    iss: 'http://localhost:4445', // The issuer of the token (your IdP)
    sub: authDetails.userId, // The subject of the token (the user id)
    aud: authDetails.client_id, // The audience of the token (the client id)
    exp: now + 3600, // The expiration time of the token (1 hour from now)
    iat: now, // The issued at time of the token (now)
    auth_time: now, // The time the user was authenticated
    nonce: authDetails.nonce, // The nonce value received from the authentication request
  };

  const idToken = jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: kid });

  res.json({
    access_token: crypto.randomBytes(32).toString('hex'),
    token_type: 'Bearer',
    expires_in: 3600,
    id_token: idToken,
  });
});

app.listen(port, () => {
  console.log(`IdP is running at http://localhost:${port}`);
});
