# oidc-access-control
## Usage

```
// build & run
docker compose up -d --build

// stop & remove
docker compose down -v
```

RP : `https://localhost:4444`, IdP : `http://localhost:4445`

## Demo

1. Access to `https://localhost:4444`
2. Click `Please log in`
3. Log in with User ID : `hoge`, Password : `hoge`
4. `Do you consent to share your information with the client?` -> Click `Yes`
5. `Submitting Callback...` -> Click `Register`
6. If `Sign up succeeded.` is displayed, you have successfully signed up.
7. Click `Login` -> Select your passkey
8. If `Sign in succeeded.` is displayed, you have successfully signed in.
9. Click `After Login Request`
10. If `After sigin in request succeeded.` is displayed, your request has been successfully processed.
11. Click `After Login Confidential Request` -> Select your passkey
12. If `After sigin in confidential request succeeded.` is displayed, your request has been successfully processed.

## Evaluation

### Setup
```
// build & run (evaluation)
docker compose -f docker-compose.evaluation.yml up -d --build
```

### Access Pattern
#### Legitimate User: Access from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/legitimate/victim_browser.py
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
after sign in result (attacker):  <p id="content">After sigin in request succeeded.</p>
```

#### Attacker: Access with victim's credential from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/credential/victim_browser.py   
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
sign in result (attacker):  <p id="content">Sign in failed.</p>
```

#### Attacker: Access with victim's credential from attacker's browser
```
docker compose -f docker-compose.evaluation.yml exec attacker bash
# python3 access_pattern/credential/attacker_browser.py   
sign in result (attacker):  <p id="content">Sign in failed.</p>
```

#### Attacker: Access with victim's id_token from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/id_token/victim_browser.py
ign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
...
sign in result (attacker):  <p id="content">Sign in failed.</p>
```

#### Attacker: Access with victim's id_token from attacker's browser
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

#### Attacker: Access with victim's session_token and secret from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/session_token/secret/victim_browser.py
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
after sign in result (attacker):  <p id="content">After sigin in request succeeded.</p>
after sign in confidential result (attacker):  <p id="content">After sigin in confidential request failed.</p>
```

#### Attacker: Access with victim's session_token and secret from attacker's browser
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

#### Attacker: Access with victim's session_token and hash from victim's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/session_token/hash/victim_browser.py
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
after sign in result (victim):  <p id="content">After sigin in request succeeded.</p>
hash:  7030e9ee35007c07c96a3c3ea6dc4dd637107b5516e496b68f8c098d3f3cbb5d
after sign in result (attacker):  {'verified': True}
```

#### Attacker: Access with victim's session_token and hash from attacker's browser
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# python3 access_pattern/session_token/hash/attacker_browser_pre.py
sign up result (victim):  <p id="content">Sign up succeeded.</p>
sign in result (victim):  <p id="content">Sign in succeeded.</p>
session_token:  s%3AiNa0QM8yHooLQabvWWgHNLy2FEgTzQkc.UvufSbkXiLJpkX8rLIJdN%2FJ3aZy%2BEkxNZVuUClaqjVE
after sign in result (victim):  <p id="content">After sigin in request succeeded.</p>
hash:  1c7565bd8474cc46476501653ac7ec398335ce4be2609a07088d6db0f7b4a44e
ok

docker compose -f docker-compose.evaluation.yml exec attacker bash
# python3 access_pattern/session_token/hash/attacker_browser.py
session_token:  s%3AiNa0QM8yHooLQabvWWgHNLy2FEgTzQkc.UvufSbkXiLJpkX8rLIJdN%2FJ3aZy%2BEkxNZVuUClaqjVE
hash:  1c7565bd8474cc46476501653ac7ec398335ce4be2609a07088d6db0f7b4a44e
sign up result (attacker):  <p id="content">Sign up succeeded.</p>
sign in result (attacker):  <p id="content">Sign in succeeded.</p>
cookies:  [{'name': 'connect.sid', 'value': 's%3AmbyT5Kj0pWZw6ZFtwZt5sjilZbe9CVcD.g3M391yC16lLbV0xq%2B5LS97vlMzbxUHeb746Zex%2B8Gk', 'domain': 'idp', 'path': '/', 'expires': -1, 'httpOnly': True, 'secure': False, 'sameSite': 'Lax'}, {'name': 'connect.sid', 'value': 's%3AiNa0QM8yHooLQabvWWgHNLy2FEgTzQkc.UvufSbkXiLJpkX8rLIJdN%2FJ3aZy%2BEkxNZVuUClaqjVE', 'domain': 'rp', 'path': '/', 'expires': -1, 'httpOnly': False, 'secure': False, 'sameSite': 'Lax'}]
after sign in result (attacker):  {'verified': False}
```

### Performance

#### Reponse Time

##### baseline
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# SAVE_TO_CSV=true python3 performance/response_time/baseline_signin.py
# SAVE_TO_CSV=true python3 performance/response_time/baseline_after_signin.py
```

##### proposed method
```
docker compose -f docker-compose.evaluation.yml exec victim bash
# SAVE_TO_CSV=true python3 performance/response_time/proposed_signin.py
# SAVE_TO_CSV=true python3 performance/response_time/proposed_after_signin.py
# SAVE_TO_CSV=true python3 performance/response_time/proposed_after_signin_confidential.py
```

#### Resource

##### baseline
```
// Execute on host machine
bash ./evaluation/performance/resource/baseline_signin.sh

// Execute same time with above script
docker compose -f docker-compose.evaluation.yml exec victim bash
# SAVE_TO_CSV=false python3 performance/response_time/baseline_signin.py
```

```
// Execute on host machine
bash ./evaluation/performance/resource/baseline_after_signin.sh

// Execute same time with above script
docker compose -f docker-compose.evaluation.yml exec victim bash
# SAVE_TO_CSV=false python3 performance/response_time/baseline_after_signin.py
```

##### proposed method
```
// Execute on host machine
bash ./evaluation/performance/resource/proposed_signin.sh

// Execute same time with above script
docker compose -f docker-compose.evaluation.yml exec victim bash
# SAVE_TO_CSV=false python3 performance/response_time/proposed_signin.py
```

```
// Execute on host machine
bash ./evaluation/performance/resource/proposed_after_signin.sh

// Execute same time with above script
docker compose -f docker-compose.evaluation.yml exec victim bash
# SAVE_TO_CSV=false python3 performance/response_time/proposed_after_signin.py
```

```
// Execute on host machine
bash ./evaluation/performance/resource/proposed_after_signin_confidential.sh

// Execute same time with above script
docker compose -f docker-compose.evaluation.yml exec victim bash
# SAVE_TO_CSV=false python3 performance/response_time/proposed_after_signin_confidential.py
```