# oidc-access-control
## Usage

```
// build & run
docker compose up -d --build

// stop & remove
docker compose down -v
```

RP : `https://localhost:443`, IdP : `http://localhost:4445`

## Demo

1. Access to `https://localhost:443`
2. Click `Please log in`
3. Log in with User ID : `hoge`, Password : `hoge`
4. `Do you consent to share your information with the client?` -> Click `Yes`
5. `Submitting Callback...` -> Click `Register`
6. If `Sign up succeeded.` is displayed, you have successfully signed up.
7. Click `Login` -> Select your passkey
8. If `Sign in succeeded.` is displayed, you have successfully signed in.

## Evaluation

### Setup
```
// build & run (evaluation)
docker compose -f docker-compose.evaluation.yml up -d --build
```

### Access with victim's credential from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/credential/victim_browser.py   
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
sign in result (attacker):  <p id="content">Sign in failed.</p>
```

### Access with victim's credential from attacker's browser
```
docker compose -f docker-compose.evaluation.yml exec attacker bash
# python3 access_pattern/credential/attacker_browser.py   
sign in result (attacker):  <p id="content">Sign in failed.</p>
```

### Access with victim's id_token from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/id_token/victim_browser.py
ign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
...
sign in result (attacker):  <p id="content">Sign in failed.</p>
```

### Access with victim's id_token from attacker's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/id_token/attacker_browser_pre.py
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
...
ok

docker compose -f docker-compose.evaluation.yml exec attacker bash
# python3 access_pattern/id_token/attacker_browser.py
sign in result (attacker):  <p id="content">Sign in failed.</p>
```

### Access with victim's session_token and secret from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/session_token/secret/victim_browser.py
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
after sign in result (attacker):  <p id="content">After sigin in request succeeded.</p>
```

### Access with victim's session_token and secret from attacker's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/session_token/secret/attacker_browser_pre.py
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
session_token:  s%3AfmPIDVycNd-X2l1IVtBSom2CYYrgWkq1.FONwNQeIEcVNR8uJzukjCGiV7SnHBQz3%2BFYL3g%2Fyyp8
secret:  54b247263b55770a9bb7f2ab4f9c7658
ok

docker compose -f docker-compose.evaluation.yml exec attacker bash
# python3 access_pattern/session_token/secret/attacker_browser.py
session_token:  s%3AfmPIDVycNd-X2l1IVtBSom2CYYrgWkq1.FONwNQeIEcVNR8uJzukjCGiV7SnHBQz3%2BFYL3g%2Fyyp8
secret:  54b247263b55770a9bb7f2ab4f9c7658
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
cookies:  [{'name': 'connect.sid', 'value': 's%3AXfrJAZ2cJ_gXzr8JZUbCnX_kdCh_IISu.2lzETWS8%2BRd50J1Y5m8twEewehXJNC65%2BazaOJgC938', 'domain': 'idp', 'path': '/', 'expires': -1, 'httpOnly': True, 'secure': False, 'sameSite': 'Lax'}, {'name': 'connect.sid', 'value': 's%3AfmPIDVycNd-X2l1IVtBSom2CYYrgWkq1.FONwNQeIEcVNR8uJzukjCGiV7SnHBQz3%2BFYL3g%2Fyyp8', 'domain': 'rp', 'path': '/', 'expires': -1, 'httpOnly': False, 'secure': False, 'sameSite': 'Lax'}]
after sign in result (attacker):  <p id="content">After sigin in request failed.</p>
```