# jwt

Minimal JWT (HS256) implementation for modern C++.

`jwt` provides a small and deterministic implementation of JSON Web
Tokens using HS256 (HMAC-SHA256).

Header-only. No heavy dependencies.

## Download

https://vixcpp.com/registry/pkg/gaspardkirira/jwt

## Why jwt?

Unlike full authentication frameworks, this library:

-   Implements HS256 signing
-   Supports verification
-   Includes built-in Base64url encoding/decoding
-   Is fully header-only
-   Has zero required dependencies beyond `hmac`
-   Is easy to integrate in small services

Perfect for:

-   API authentication
-   Stateless session tokens
-   Microservices
-   CLI tools
-   Embedded systems
-   Internal tooling

## Installation

### Using Vix Registry

``` bash
vix add gaspardkirira/jwt
vix deps
```

This will automatically install:

-   `gaspardkirira/hmac`
-   `gaspardkirira/hashing` (transitive)

### Manual

Clone the repository:

``` bash
git clone https://github.com/GaspardKirira/jwt.git
```

Add the `include/` directory to your project and ensure `hmac` (and its
dependency `hashing`) are available.

## Quick Example

``` cpp
#include <jwt/jwt.hpp>
#include <iostream>

int main()
{
  std::string secret = "supersecret";
  std::string payload = R"({"sub":"123","name":"Alice"})";

  std::string token = jwt::encode(payload, secret);

  std::cout << "token: " << token << "\n";
  std::cout << "verify: "
            << (jwt::verify(token, secret) ? "ok" : "fail")
            << "\n";
}
```

## Decode Without Verification

``` cpp
#include <jwt/jwt.hpp>
#include <iostream>

int main()
{
  std::string secret = "secret";
  std::string payload = R"({"role":"admin"})";

  std::string token = jwt::encode(payload, secret);

  std::string decoded = jwt::decode_without_verify(token);

  std::cout << decoded << "\n";
}
```

## API Overview

``` cpp
jwt::encode(payload_json, secret);

jwt::verify(token, secret);

jwt::decode_without_verify(token);
```

## Cryptographic Notes

-   Algorithm: HS256 (HMAC-SHA256)
-   Signature computed using `hmac`
-   Base64url encoding (no padding)
-   Deterministic output
-   No global state

This implementation intentionally focuses on HS256 only. It does not
implement:

-   RS256
-   ES256
-   exp/iat validation
-   Claim validation logic

You are responsible for validating claims such as `exp`, `nbf`, `iat`.

## Tests

Run:

``` bash
vix build
vix tests
```

Includes encode, verify, and roundtrip validation tests.

## Design Philosophy

`jwt` focuses on:

-   Minimal surface area
-   Clear and explicit APIs
-   Deterministic behavior
-   Small integration footprint
-   No hidden magic

Designed for modern C++ systems where simplicity matters.

## License

MIT License
Copyright (c) Gaspard Kirira

