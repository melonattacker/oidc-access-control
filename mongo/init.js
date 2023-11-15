db = db.getSiblingDB('oidc-access-control');

db.createUser({
    user: 'user',
    pwd: 'pass',
    roles: [{ role: 'readWrite', db: 'oidc-access-control' }],
});