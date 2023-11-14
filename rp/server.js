const express = require('express');
const crypto = require('crypto');
const path = require('path');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const axios = require('axios');
const jwksClient = require('jwks-rsa');

const app = express();
const port = 4444;

// middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'), // Replace with your own session secret
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // In production, set to true and use HTTPS
}));

const clientID = 'client';
const redirectUri = `http://localhost:${port}/callback`;
const idpUrl = 'http://idp:4445';

const client = jwksClient({
  jwksUri: `${idpUrl}/.well-known/jwks.json`
});

const users = {};

function getKey(header, callback){
  client.getSigningKey(header.kid, function(err, key) {
    var signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// send authentication request to IdP
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex')
  const url = new URL(`http://localhost:4445/authorize`);
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
  res.sendFile(path.join(__dirname, './html/callback.html'));
});

// process ID token
app.post('/callback', async (req, res) => {
  try {
    const { idToken } = req.body;

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

    // Check if user exists or create a new one
    const userId = decoded.sub; // Assuming sub claim is the user identifier
    if (!users[userId]) {
      users[userId] = { userId, data: decoded }; // Simple user registration
    }

    // Set session information
    req.session.userId = userId;

    res.json({ status: 'Logged in', userId: userId });
  } catch (error) {
    res.status(400).send(`Invalid ID token: ${error.message}`);
  }
});

app.listen(port, () => {
  console.log(`RP is running at http://localhost:${port}`);
});
