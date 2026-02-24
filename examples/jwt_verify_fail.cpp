#include <jwt/jwt.hpp>

#include <iostream>
#include <string>

int main()
{
  const std::string secret = "supersecret";
  const std::string payload = R"({"sub":"123"})";

  const std::string token = jwt::encode(payload, secret);

  std::cout << "verify correct secret : "
            << (jwt::verify(token, secret) ? "ok" : "fail") << "\n";

  std::cout << "verify wrong secret   : "
            << (jwt::verify(token, "wrongsecret") ? "ok" : "fail") << "\n";

  return 0;
}
