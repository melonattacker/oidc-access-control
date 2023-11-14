# Generate RSA keys

```:bash
# RSA 秘密鍵の生成
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# 対応する公開鍵の生成
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

# Generate JWK
Use https://russelldavies.github.io/jwk-creator/

Specify the following parameters:
- Public Key Use: `Signing`
- Algorithm: `RS256`
- Key ID: `1b4cae83f17f2a89c4a775a1f88f6aed9e04196fe0e3fb78b4b9cc47a6c0dcf1`
- PEM encoded key: Content of `public_key.pem`