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

### Threat1 : Access with victim's credential from victim's browser
### Threat2 : Access with victim's credential from attacker's browser