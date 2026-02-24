#include <jwt/jwt.hpp>

#include <iostream>
#include <string>

int main()
{
  const std::string secret = "supersecret";
  const std::string payload = R"({"sub":"42","role":"admin"})";

  const std::string token = jwt::encode(payload, secret);

  const std::string decoded = jwt::decode_without_verify(token);

  std::cout << "decoded payload:\n"
            << decoded << "\n";
  return 0;
}
