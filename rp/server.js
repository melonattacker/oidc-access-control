const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = 3000;

const clientID = 'client';
const redirectUri = `http://localhost:${port}/callback`;

// send authentication request to IdP
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex')
  const url = new URL(`http://localhost:3001/authorize`);
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

app.listen(port, () => {
  console.log(`RP is running at http://localhost:${port}`);
});
