#include <jwt/jwt.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

static void expect_true(bool v, const char *msg)
{
  if (!v)
  {
    std::cerr << "FAIL: " << msg << "\n";
    std::exit(1);
  }
}

int main()
{
  const std::string payload = R"({"sub":"123","name":"Alice"})";
  const std::string secret = "supersecret";

  const std::string token = jwt::encode(payload, secret);

  expect_true(jwt::verify(token, secret), "valid token must verify");
  expect_true(!jwt::verify(token, "wrongsecret"), "wrong secret must fail");

  const std::string decoded = jwt::decode_without_verify(token);
  expect_true(decoded == payload, "payload roundtrip");

  std::cout << "ok\n";
  return 0;
}
