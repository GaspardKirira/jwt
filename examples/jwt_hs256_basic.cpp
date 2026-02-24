#include <jwt/jwt.hpp>

#include <iostream>
#include <string>

int main()
{
  const std::string secret = "supersecret";
  const std::string payload = R"({"sub":"123","name":"Alice"})";

  const std::string token = jwt::encode(payload, secret);

  std::cout << "token  : " << token << "\n";
  std::cout << "verify : " << (jwt::verify(token, secret) ? "ok" : "fail") << "\n";
  return 0;
}
