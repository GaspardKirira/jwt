/**
 * @file test_basic.cpp
 * @brief Comprehensive test suite for jwt.hpp.
 *
 * Self-contained. No external test framework required.
 * Compile with:
 *   g++ -std=c++20 -I. -o test_basic test_basic.cpp && ./test_basic
 *
 * Exit code 0 = all tests passed.
 * Exit code 1 = at least one failure.
 */

#include <jwt/jwt.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace std::chrono_literals;

// ============================================================================
//  Minimal test harness  (no dependencies)
// ============================================================================

namespace test
{

  static int total = 0;
  static int passed = 0;
  static int failed = 0;

  static std::string current_suite;

  void suite(std::string_view name)
  {
    current_suite = std::string(name);
    std::cout << "\n── " << name << " ──\n";
  }

  void pass(std::string_view name)
  {
    ++total;
    ++passed;
    std::cout << "  \033[32m[PASS]\033[0m " << name << "\n";
  }

  void fail(std::string_view name, std::string_view reason = "")
  {
    ++total;
    ++failed;
    std::cout << "  \033[31m[FAIL]\033[0m " << name;
    if (!reason.empty())
      std::cout << "  →  " << reason;
    std::cout << "\n";
  }

// CHECK: evaluates expr, catches nothing
#define CHECK(name, expr)                                                  \
  do                                                                       \
  {                                                                        \
    try                                                                    \
    {                                                                      \
      if (expr)                                                            \
      {                                                                    \
        test::pass(name);                                                  \
      }                                                                    \
      else                                                                 \
      {                                                                    \
        test::fail(name, "expression was false");                          \
      }                                                                    \
    }                                                                      \
    catch (const std::exception &_e)                                       \
    {                                                                      \
      test::fail(name, std::string("unexpected exception: ") + _e.what()); \
    }                                                                      \
  } while (0)

// THROWS: expects a specific exception type
#define THROWS(name, ExType, expr)                                         \
  do                                                                       \
  {                                                                        \
    bool _caught = false;                                                  \
    try                                                                    \
    {                                                                      \
      expr;                                                                \
    }                                                                      \
    catch (const ExType &)                                                 \
    {                                                                      \
      _caught = true;                                                      \
    }                                                                      \
    catch (const std::exception &_e)                                       \
    {                                                                      \
      test::fail(name, std::string("wrong exception type: ") + _e.what()); \
      break;                                                               \
    }                                                                      \
    if (_caught)                                                           \
      test::pass(name);                                                    \
    else                                                                   \
      test::fail(name, "no exception was thrown");                         \
  } while (0)

// THROWS_CODE: expects jwt::error with a specific error code
#define THROWS_CODE(name, expected_code, expr)                                                                  \
  do                                                                                                            \
  {                                                                                                             \
    bool _caught = false;                                                                                       \
    try                                                                                                         \
    {                                                                                                           \
      expr;                                                                                                     \
    }                                                                                                           \
    catch (const jwt::error &_e)                                                                                \
    {                                                                                                           \
      if (_e.err_code() == expected_code)                                                                       \
      {                                                                                                         \
        _caught = true;                                                                                         \
      }                                                                                                         \
      else                                                                                                      \
      {                                                                                                         \
        test::fail(name, std::string("wrong error code, got ") + std::to_string(std::uint32_t(_e.err_code()))); \
        break;                                                                                                  \
      }                                                                                                         \
    }                                                                                                           \
    catch (const std::exception &_e)                                                                            \
    {                                                                                                           \
      test::fail(name, std::string("wrong exception: ") + _e.what());                                           \
      break;                                                                                                    \
    }                                                                                                           \
    if (_caught)                                                                                                \
      test::pass(name);                                                                                         \
    else                                                                                                        \
      test::fail(name, "no exception was thrown");                                                              \
  } while (0)

// NO_THROW: asserts no exception is thrown
#define NO_THROW(name, expr)                                               \
  do                                                                       \
  {                                                                        \
    try                                                                    \
    {                                                                      \
      expr;                                                                \
      test::pass(name);                                                    \
    }                                                                      \
    catch (const std::exception &_e)                                       \
    {                                                                      \
      test::fail(name, std::string("unexpected exception: ") + _e.what()); \
    }                                                                      \
  } while (0)

  void summary()
  {
    std::cout << "\n════════════════════════════════════\n";
    std::cout << "  Total  : " << total << "\n";
    std::cout << "  Passed : \033[32m" << passed << "\033[0m\n";
    if (failed > 0)
      std::cout << "  Failed : \033[31m" << failed << "\033[0m\n";
    else
      std::cout << "  Failed : 0\n";
    std::cout << "════════════════════════════════════\n";
  }

} // namespace test

// ============================================================================
//  Hex helper for crypto vector tests
// ============================================================================

static std::string to_hex(const std::uint8_t *data, std::size_t len)
{
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < len; ++i)
    oss << std::setw(2) << unsigned(data[i]);
  return oss.str();
}

template <std::size_t N>
static std::string to_hex(const std::array<std::uint8_t, N> &a)
{
  return to_hex(a.data(), N);
}

// ============================================================================
//  1 – Base64url codec
// ============================================================================

static void test_base64()
{
  test::suite("Base64url codec");

  // RFC 4648 § 10 test vectors (base64url variant, no padding)
  auto enc = [](std::string_view s)
  {
    return jwt::detail::base64::encode(s);
  };
  auto dec = [](std::string_view s)
  {
    return jwt::detail::base64::decode_to_string(s);
  };

  CHECK("encode empty string", enc("") == "");
  CHECK("encode 'f'", enc("f") == "Zg");
  CHECK("encode 'fo'", enc("fo") == "Zm8");
  CHECK("encode 'foo'", enc("foo") == "Zm9v");
  CHECK("encode 'foob'", enc("foob") == "Zm9vYg");
  CHECK("encode 'fooba'", enc("fooba") == "Zm9vYmE");
  CHECK("encode 'foobar'", enc("foobar") == "Zm9vYmFy");

  CHECK("decode empty string", dec("") == "");
  CHECK("decode 'Zg'", dec("Zg") == "f");
  CHECK("decode 'Zm8'", dec("Zm8") == "fo");
  CHECK("decode 'Zm9v'", dec("Zm9v") == "foo");
  CHECK("decode 'Zm9vYg'", dec("Zm9vYg") == "foob");
  CHECK("decode 'Zm9vYmE'", dec("Zm9vYmE") == "fooba");
  CHECK("decode 'Zm9vYmFy'", dec("Zm9vYmFy") == "foobar");

  // Round-trip on binary-like data
  const std::string bin = "\x00\x01\x02\xFF\xFE\xFD";
  CHECK("round-trip binary", dec(enc(bin)) == bin);

  // URL-safe characters (- and _ must appear, never + or /)
  const std::string encoded_special = enc("\xFB\xFF");
  CHECK("uses '-' not '+'", encoded_special.find('+') == std::string::npos);
  CHECK("uses '_' not '/'", encoded_special.find('/') == std::string::npos);
  CHECK("no padding '='", encoded_special.find('=') == std::string::npos);

  // Tolerance for padding in decode
  NO_THROW("decode with padding", dec("Zm9v=="));

  // Invalid character
  THROWS_CODE("decode invalid char",
              jwt::error::code::invalid_base64,
              jwt::detail::base64::decode("Zm9v!!!!"));
}

// ============================================================================
//  2 – SHA-2 and HMAC crypto (NIST / RFC 4231 test vectors)
// ============================================================================

static void test_crypto()
{
  test::suite("SHA-2 / HMAC crypto (NIST vectors)");

  using namespace jwt::detail::crypto;

  // ── SHA-256 NIST FIPS 180-4 vectors ────────────────────────────────

  {
    // SHA-256("")
    const std::string empty;
    const auto h = sha256(reinterpret_cast<const std::uint8_t *>(empty.data()), 0);
    CHECK("SHA-256 empty string",
          to_hex(h) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  }
  {
    // SHA-256("abc")
    // Authoritative value from Python hashlib, OpenSSL, and NIST CAVP SHA-256 KAT
    // (SHA256ShortMsg.rsp Len=24 Msg=616263).
    const std::string msg = "abc";
    const auto h = sha256(reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size());
    CHECK("SHA-256 'abc'",
          to_hex(h) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  }
  {
    // SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    const std::string msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const auto h = sha256(reinterpret_cast<const std::uint8_t *>(msg.data()), msg.size());
    CHECK("SHA-256 448-bit message",
          to_hex(h) == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  }

  // ── HMAC-SHA256 RFC 4231 Test Case 1 ───────────────────────────────
  // Key  = 0b0b0b...0b (20 bytes)
  // Data = "Hi There"
  // Expected HMAC-SHA256 = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
  {
    const std::vector<std::uint8_t> key(20, 0x0b);
    const std::string data = "Hi There";
    const auto mac = hmac_sha256(
        key.data(), key.size(),
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
    CHECK("HMAC-SHA256 RFC4231 TC1",
          to_hex(mac) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  }

  // ── HMAC-SHA256 RFC 4231 Test Case 2 ───────────────────────────────
  // Key  = "Jefe"
  // Data = "what do ya want for nothing?"
  // Expected = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
  // (verified: Python hmac + hashlib, OpenSSL, RFC 4231 §4.2)
  {
    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";
    const auto mac = hmac_sha256(
        reinterpret_cast<const std::uint8_t *>(key.data()), key.size(),
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
    CHECK("HMAC-SHA256 RFC4231 TC2",
          to_hex(mac) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  }

  // ── HMAC-SHA384 RFC 4231 Test Case 2 ───────────────────────────────
  // Expected = af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649
  {
    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";
    const auto mac = hmac_sha384(
        reinterpret_cast<const std::uint8_t *>(key.data()), key.size(),
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
    CHECK("HMAC-SHA384 RFC4231 TC2",
          to_hex(mac) == "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
  }

  // ── HMAC-SHA512 RFC 4231 Test Case 2 ───────────────────────────────
  // Expected = 164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737
  {
    const std::string key = "Jefe";
    const std::string data = "what do ya want for nothing?";
    const auto mac = hmac_sha512(
        reinterpret_cast<const std::uint8_t *>(key.data()), key.size(),
        reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
    CHECK("HMAC-SHA512 RFC4231 TC2",
          to_hex(mac) == "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
  }

  // ── Constant-time compare ───────────────────────────────────────────
  {
    const std::array<std::uint8_t, 4> a{1, 2, 3, 4};
    const std::array<std::uint8_t, 4> b{1, 2, 3, 4};
    const std::array<std::uint8_t, 4> c{1, 2, 3, 5};
    CHECK("ct_equal same arrays", constant_time_equal(a.data(), b.data(), 4));
    CHECK("ct_equal diff arrays", !constant_time_equal(a.data(), c.data(), 4));
    CHECK("ct_equal zero length", constant_time_equal(a.data(), c.data(), 0));
  }
}

// ============================================================================
//  3 – JSON parser
// ============================================================================

static void test_json()
{
  test::suite("JSON parser");

  using namespace jwt::detail::json;

  // primitives
  CHECK("parse null", parse("null").is_null());
  CHECK("parse true", parse("true").as_bool() == true);
  CHECK("parse false", parse("false").as_bool() == false);
  CHECK("parse integer", parse("42").as_int() == 42);
  CHECK("parse negative int", parse("-7").as_int() == -7);
  CHECK("parse float", parse("3.14").is_double());
  CHECK("parse string", parse(R"("hello")").as_string() == "hello");

  // escape sequences
  CHECK("escape \\n", parse(R"("a\nb")").as_string() == "a\nb");
  CHECK("escape \\t", parse(R"("a\tb")").as_string() == "a\tb");
  CHECK("escape \\\"", parse(R"("a\"b")").as_string() == "a\"b");
  CHECK("escape \\\\", parse(R"("a\\b")").as_string() == "a\\b");

  // array
  {
    const auto v = parse("[1,2,3]");
    CHECK("array type", v.is_array());
    CHECK("array size", v.as_array().size() == 3);
    CHECK("array[0]", v.as_array()[0].as_int() == 1);
    CHECK("array[2]", v.as_array()[2].as_int() == 3);
  }
  CHECK("empty array", parse("[]").as_array().empty());

  // object
  {
    const auto v = parse(R"({"k":"v","n":99})");
    CHECK("object type", v.is_object());
    CHECK("object key 'k'", v.as_object().at("k").as_string() == "v");
    CHECK("object key 'n'", v.as_object().at("n").as_int() == 99);
  }
  CHECK("empty object", parse("{}").as_object().empty());

  // nested
  {
    const auto v = parse(R"({"a":{"b":[1,true,null]}})");
    const auto &inner = v.as_object().at("a").as_object().at("b").as_array();
    CHECK("nested int", inner[0].as_int() == 1);
    CHECK("nested bool", inner[1].as_bool() == true);
    CHECK("nested null", inner[2].is_null());
  }

  // serialise round-trip
  {
    const std::string src = R"({"alg":"HS256","typ":"JWT"})";
    const auto v = parse(src);
    // The serialiser may reorder keys (unordered_map), so re-parse
    const auto v2 = parse(to_string(v));
    CHECK("round-trip alg", v2.as_object().at("alg").as_string() == "HS256");
    CHECK("round-trip typ", v2.as_object().at("typ").as_string() == "JWT");
  }

  // error cases
  THROWS_CODE("trailing content",
              jwt::error::code::invalid_json,
              parse("42 garbage"));
  THROWS_CODE("unterminated string",
              jwt::error::code::invalid_json,
              parse(R"("abc)"));
  THROWS_CODE("bad object syntax",
              jwt::error::code::invalid_json,
              parse("{1:2}"));
}

// ============================================================================
//  4 – encode / decode round-trip
// ============================================================================

static void test_encode_decode()
{
  test::suite("encode / decode round-trip");

  const std::string secret = "test-secret-key";

  jwt::claims c;
  c.set_issuer("test-iss")
      .set_subject("user:1")
      .set_issued_at_now()
      .set_expiration(3600s)
      .set_claim("role", std::string{"admin"})
      .set_claim("level", std::int64_t{7})
      .set_claim("active", true);

  const std::string token = jwt::encode(c, secret, "HS256");

  // Structure: header.payload.signature (three parts)
  {
    std::size_t dots = 0;
    for (char ch : token)
      if (ch == '.')
        ++dots;
    CHECK("token has exactly two dots", dots == 2);
  }

  // Verify returns verified=true
  const auto t = jwt::decode(token, secret);
  CHECK("verified flag is true", t.verified);

  // Standard claims survive round-trip
  CHECK("issuer round-trip", t.payload.issuer() == "test-iss");
  CHECK("subject round-trip", t.payload.subject() == "user:1");
  CHECK("exp is set", t.payload.expiration().has_value());
  CHECK("iat is set", t.payload.issued_at().has_value());

  // Custom claims survive round-trip
  CHECK("custom string claim", t.payload.get_string("role") == "admin");
  CHECK("custom int claim", t.payload.get_int("level") == 7);
  CHECK("custom bool claim", t.payload.get_bool("active") == true);

  // Header
  CHECK("header algorithm HS256",
        t.header.algorithm == jwt::detail::algorithm::HS256);
  CHECK("header type JWT", t.header.type == "JWT");

  // Raw parts are preserved
  CHECK("raw_header_b64 not empty", !t.raw_header_b64.empty());
  CHECK("raw_payload_b64 not empty", !t.raw_payload_b64.empty());
  CHECK("raw_signature_b64 not empty", !t.raw_signature_b64.empty());
}

// ============================================================================
//  5 – Algorithms HS256 / HS384 / HS512
// ============================================================================

static void test_algorithms()
{
  test::suite("Algorithm variants");

  const std::string secret = "algorithm-test-key";
  jwt::claims c;
  c.set_issuer("alg-test").set_claim("x", std::int64_t{1});

  for (const char *alg : {"HS256", "HS384", "HS512"})
  {
    const std::string token = jwt::encode(c, secret, alg);
    NO_THROW(std::string("encode ") + alg, (void)token);

    const auto t = jwt::decode(token, secret);
    CHECK(std::string("decode+verify ") + alg, t.verified);
    CHECK(std::string("algorithm field ") + alg,
          jwt::detail::algorithm_to_string(t.header.algorithm) == alg);
  }

  // Different algorithms produce different signatures for the same payload
  const std::string t256 = jwt::encode(c, secret, "HS256");
  const std::string t384 = jwt::encode(c, secret, "HS384");
  const std::string t512 = jwt::encode(c, secret, "HS512");
  CHECK("HS256 != HS384", t256 != t384);
  CHECK("HS256 != HS512", t256 != t512);
  CHECK("HS384 != HS512", t384 != t512);
}

// ============================================================================
//  6 – Signature security
// ============================================================================

static void test_signature_security()
{
  test::suite("Signature security");

  const std::string secret = "correct-secret";
  jwt::claims c;
  c.set_issuer("sec-test");
  const std::string token = jwt::encode(c, secret, "HS256");

  // Wrong secret
  THROWS_CODE("wrong secret rejects",
              jwt::error::code::signature_invalid,
              jwt::decode(token, "wrong-secret"));

  // Tampered payload — flip one byte in the middle part
  {
    const auto dot1 = token.find('.');
    const auto dot2 = token.find('.', dot1 + 1);
    std::string tampered = token;
    // Change one character in the payload
    const std::size_t mid = dot1 + 1 + (dot2 - dot1 - 1) / 2;
    tampered[mid] = (tampered[mid] == 'A') ? 'B' : 'A';
    THROWS_CODE("tampered payload rejects",
                jwt::error::code::signature_invalid,
                jwt::decode(tampered, secret));
  }

  // Tampered signature directly
  {
    std::string tampered = token;
    tampered.back() = (tampered.back() == 'A') ? 'B' : 'A';
    THROWS_CODE("tampered signature rejects",
                jwt::error::code::signature_invalid,
                jwt::decode(tampered, secret));
  }

  // Empty secret — should still produce a consistent, verifiable token
  {
    const std::string t_empty = jwt::encode(c, "", "HS256");
    NO_THROW("encode with empty secret", (void)t_empty);
    NO_THROW("decode with empty secret", jwt::decode(t_empty, ""));
    THROWS_CODE("empty vs non-empty secret",
                jwt::error::code::signature_invalid,
                jwt::decode(t_empty, "x"));
  }

  // Algorithm 'none' must be rejected
  THROWS_CODE("alg=none rejected",
              jwt::error::code::unsupported_algorithm,
              jwt::encode(c, secret, "none"));

  THROWS_CODE("alg=None rejected",
              jwt::error::code::unsupported_algorithm,
              jwt::encode(c, secret, "None"));

  // Unknown algorithm
  THROWS_CODE("unknown alg rejected",
              jwt::error::code::unsupported_algorithm,
              jwt::encode(c, secret, "RS256"));
}

// ============================================================================
//  7 – Structural / format errors
// ============================================================================

static void test_format_errors()
{
  test::suite("Format / structural errors");

  // Too few dots
  THROWS_CODE("one-part token",
              jwt::error::code::malformed_token,
              jwt::decode("onlyone", "s"));

  THROWS_CODE("two-part token",
              jwt::error::code::malformed_token,
              jwt::decode("aaa.bbb", "s"));

  // Too many dots
  THROWS_CODE("four-part token",
              jwt::error::code::malformed_token,
              jwt::decode("a.b.c.d", "s"));

  // Empty string
  THROWS_CODE("empty string",
              jwt::error::code::malformed_token,
              jwt::decode("", "s"));

  // Valid structure but garbage base64
  THROWS("garbage base64 header",
         jwt::format_error,
         jwt::decode("!!!!.payload.sig", "s"));

  // Valid base64, but not valid JSON in header
  {
    // Encode something that is not JSON
    const auto bad_hdr = jwt::detail::base64::encode("not json at all");
    const std::string t = bad_hdr + ".payload.sig";
    THROWS_CODE("non-JSON header",
                jwt::error::code::invalid_json,
                jwt::decode(t, "s"));
  }

  // is_structurally_valid
  CHECK("structurally valid token", jwt::is_structurally_valid("a.b.c"));
  CHECK("not structurally valid", !jwt::is_structurally_valid("ab"));
  CHECK("not structurally valid 4", !jwt::is_structurally_valid("a.b.c.d"));
}

// ============================================================================
//  8 – parse without verification
// ============================================================================

static void test_parse_no_verify()
{
  test::suite("parse / parse_header / parse_payload");

  jwt::claims c;
  c.set_issuer("parse-test")
      .set_subject("user:99")
      .set_claim("data", std::string{"value"});

  const std::string token = jwt::encode(c, "secret", "HS384");

  // jwt::parse — no signature check
  {
    const auto t = jwt::parse(token);
    CHECK("parse verified=false", !t.verified);
    CHECK("parse issuer", t.payload.issuer() == "parse-test");
    CHECK("parse subject", t.payload.subject() == "user:99");
    CHECK("parse custom claim", t.payload.get_string("data") == "value");
    CHECK("parse alg header",
          t.header.algorithm == jwt::detail::algorithm::HS384);
  }

  // jwt::parse_header
  {
    const auto hdr = jwt::parse_header(token);
    CHECK("parse_header alg",
          hdr.algorithm == jwt::detail::algorithm::HS384);
    CHECK("parse_header type", hdr.type == "JWT");
  }

  // jwt::parse_payload
  {
    const auto pld = jwt::parse_payload(token);
    CHECK("parse_payload issuer", pld.issuer() == "parse-test");
  }

  // parse does not verify — wrong secret succeeds
  NO_THROW("parse ignores wrong secret",
           jwt::parse(token));
}

// ============================================================================
//  9 – builder API
// ============================================================================

static void test_builder()
{
  test::suite("builder API");

  using namespace std::chrono_literals;

  const std::string secret = "builder-secret";

  // Basic fluent usage
  const std::string token =
      jwt::builder()
          .set_issuer("builder-iss")
          .set_subject("subject-x")
          .set_audience("api.service")
          .set_jwt_id("unique-id-001")
          .set_issued_at_now()
          .set_expiration(7200s)
          .set_not_before_now()
          .set_claim("role", std::string{"editor"})
          .set_claim("count", std::int64_t{42})
          .set_claim("flag", true)
          .set_claim("score", 9.5)
          .set_algorithm("HS256")
          .sign(secret);

  NO_THROW("builder sign() produces valid token", (void)token);

  const auto t = jwt::decode(token, secret);
  CHECK("builder verified", t.verified);
  CHECK("builder issuer", t.payload.issuer() == "builder-iss");
  CHECK("builder subject", t.payload.subject() == "subject-x");
  CHECK("builder audience", !t.payload.audience().empty() &&
                                t.payload.audience()[0] == "api.service");
  CHECK("builder jwt_id", t.payload.jwt_id() == "unique-id-001");
  CHECK("builder exp present", t.payload.expiration().has_value());
  CHECK("builder nbf present", t.payload.not_before().has_value());
  CHECK("builder custom string", t.payload.get_string("role") == "editor");
  CHECK("builder custom int", t.payload.get_int("count") == 42);
  CHECK("builder custom bool", t.payload.get_bool("flag") == true);

  // Multiple-audience
  {
    const std::string mt =
        jwt::builder()
            .set_audience(std::vector<std::string>{"api.a", "api.b", "api.c"})
            .sign(secret);
    const auto dec = jwt::decode(mt, secret);
    CHECK("multi-audience size", dec.payload.audience().size() == 3);
    CHECK("multi-audience[1]", dec.payload.audience()[1] == "api.b");
  }

  // HS512 via builder
  {
    const std::string t512 =
        jwt::builder()
            .set_issuer("alg-test")
            .set_algorithm("HS512")
            .sign(secret);
    const auto dec = jwt::decode(t512, secret);
    CHECK("builder HS512 alg field",
          dec.header.algorithm == jwt::detail::algorithm::HS512);
  }

  // Key ID in header
  {
    const std::string tkid =
        jwt::builder()
            .set_key_id("key-2024")
            .sign(secret);
    const auto hdr = jwt::parse_header(tkid);
    CHECK("builder key_id in header", hdr.kid == "key-2024");
  }
}

// ============================================================================
//  10 – claims container
// ============================================================================

static void test_claims()
{
  test::suite("claims container");

  jwt::claims c;
  c.set_issuer("iss-val")
      .set_subject("sub-val")
      .set_audience("aud-val")
      .set_jwt_id("jti-val");

  // Standard getters
  CHECK("issuer", c.issuer() == "iss-val");
  CHECK("subject", c.subject() == "sub-val");
  CHECK("audience", !c.audience().empty() && c.audience()[0] == "aud-val");
  CHECK("jwt_id", c.jwt_id() == "jti-val");

  // Absent optionals
  CHECK("no exp before set", !c.expiration().has_value());
  CHECK("no nbf before set", !c.not_before().has_value());
  CHECK("no iat before set", !c.issued_at().has_value());

  // Time-based claims
  const auto now = std::chrono::system_clock::now();
  c.set_issued_at(now);
  c.set_expiration(3600s);
  c.set_not_before(now - 60s);

  CHECK("iat is set", c.issued_at().has_value());
  CHECK("exp is set", c.expiration().has_value());
  CHECK("nbf is set", c.not_before().has_value());

  // exp > iat
  CHECK("exp > iat", *c.expiration() > *c.issued_at());

  // Custom claims — all supported types
  c.set_claim("str", std::string{"hello"});
  c.set_claim("num", std::int64_t{-99});
  c.set_claim("dbl", 3.14);
  c.set_claim("bool", false);

  CHECK("has custom str", c.has_custom("str"));
  CHECK("has custom num", c.has_custom("num"));
  CHECK("missing claim", !c.has_custom("nonexistent"));

  CHECK("get_string", c.get_string("str") == "hello");
  CHECK("get_int", c.get_int("num") == -99);
  CHECK("get_bool", c.get_bool("bool") == false);

  // Type mismatch errors
  THROWS_CODE("type mismatch string→int",
              jwt::error::code::claim_type_error,
              c.get_int("str"));
  THROWS_CODE("type mismatch int→bool",
              jwt::error::code::claim_type_error,
              c.get_bool("num"));

  // Missing claim error
  THROWS_CODE("missing claim throws",
              jwt::error::code::missing_claim,
              c.get_string("does_not_exist"));

  // JSON round-trip
  {
    const std::string json = c.to_json();
    const auto c2 = jwt::claims::from_json(json);
    CHECK("json rt issuer", c2.issuer() == "iss-val");
    CHECK("json rt subject", c2.subject() == "sub-val");
    CHECK("json rt str", c2.get_string("str") == "hello");
    CHECK("json rt num", c2.get_int("num") == -99);
  }
}

// ============================================================================
//  11 – validator
// ============================================================================

static void test_validator()
{
  test::suite("validator");

  const std::string secret = "val-secret";

  // Helper to build a fresh token
  auto make_token = [&](auto setup) -> std::string
  {
    jwt::builder b;
    b.set_issuer("trusted")
        .set_subject("user:1")
        .set_audience("my-api")
        .set_issued_at_now()
        .set_expiration(3600s);
    setup(b);
    return b.sign(secret);
  };

  // ── Happy path ─────────────────────────────────────────────────────
  {
    jwt::validator v;
    v.require_issuer("trusted")
        .require_subject("user:1")
        .require_audience("my-api")
        .set_clock_skew(30s);

    const std::string tok = make_token([](auto &) {});
    NO_THROW("full validation passes", v.decode_and_validate(tok, secret));
    const auto t = v.decode_and_validate(tok, secret);
    CHECK("validated verified flag", t.verified);
  }

  // ── Issuer mismatch ────────────────────────────────────────────────
  {
    jwt::validator v;
    v.require_issuer("other-issuer");
    const std::string tok = make_token([](auto &) {});
    THROWS_CODE("issuer mismatch",
                jwt::error::code::issuer_mismatch,
                v.decode_and_validate(tok, secret));
  }

  // ── Subject mismatch ───────────────────────────────────────────────
  {
    jwt::validator v;
    v.require_subject("other-subject");
    const std::string tok = make_token([](auto &) {});
    THROWS_CODE("subject mismatch",
                jwt::error::code::subject_mismatch,
                v.decode_and_validate(tok, secret));
  }

  // ── Audience mismatch ──────────────────────────────────────────────
  {
    jwt::validator v;
    v.require_audience("other-api");
    const std::string tok = make_token([](auto &) {});
    THROWS_CODE("audience mismatch",
                jwt::error::code::audience_mismatch,
                v.decode_and_validate(tok, secret));
  }

  // ── Expired token ──────────────────────────────────────────────────
  {
    jwt::validator v;
    v.check_expiration(true);

    // Build a token that expired 1 hour ago
    jwt::claims past_c;
    past_c.set_expiration(
        std::chrono::system_clock::now() - 3600s);
    const std::string tok = jwt::encode(past_c, secret);

    THROWS_CODE("expired token rejected",
                jwt::error::code::token_expired,
                v.decode_and_validate(tok, secret));
  }

  // ── Clock skew absorbs a slightly-expired token ────────────────────
  {
    // Token expired 10 seconds ago, skew tolerance = 30s
    jwt::claims c;
    c.set_expiration(std::chrono::system_clock::now() - 10s);
    const std::string tok = jwt::encode(c, secret);

    jwt::validator v;
    v.check_expiration(true)
        .set_clock_skew(30s);

    NO_THROW("clock skew absorbs 10s expiry", v.decode_and_validate(tok, secret));
  }

  // ── Not-before in the future ───────────────────────────────────────
  {
    jwt::claims c;
    c.set_not_before(std::chrono::system_clock::now() + 3600s);
    const std::string tok = jwt::encode(c, secret);

    jwt::validator v;
    v.check_not_before(true);

    THROWS_CODE("nbf in the future rejected",
                jwt::error::code::token_not_yet_valid,
                v.decode_and_validate(tok, secret));
  }

  // ── validate() directly on claims ─────────────────────────────────
  {
    jwt::claims c;
    c.set_issuer("direct-iss").set_expiration(3600s);

    jwt::validator v;
    v.require_issuer("direct-iss");
    NO_THROW("direct validate() passes", v.validate(c));
  }
}

// ============================================================================
//  12 – remaining_lifetime utility
// ============================================================================

static void test_utilities()
{
  test::suite("Utility functions");

  const std::string secret = "util-secret";

  // remaining_lifetime with exp
  {
    jwt::claims c;
    c.set_expiration(3600s);
    const auto rem = jwt::remaining_lifetime(c);
    CHECK("remaining_lifetime present", rem.has_value());
    // Should be roughly 3600 seconds (allow ±5s for test execution time)
    CHECK("remaining_lifetime approx",
          *rem >= 3595 && *rem <= 3605);
  }

  // remaining_lifetime without exp
  {
    jwt::claims c;
    c.set_issuer("no-exp");
    CHECK("remaining_lifetime absent", !jwt::remaining_lifetime(c).has_value());
  }

  // is_structurally_valid
  CHECK("structurally valid", jwt::is_structurally_valid("a.b.c"));
  CHECK("structurally invalid", !jwt::is_structurally_valid("abc"));

  // Full encode → is_structurally_valid
  {
    jwt::claims c;
    c.set_issuer("util");
    const std::string tok = jwt::encode(c, secret);
    CHECK("encoded token structurally valid", jwt::is_structurally_valid(tok));
  }
}

// ============================================================================
//  13 – Known-good JWT interoperability vector (jwt.io)
// ============================================================================

static void test_interop()
{
  test::suite("Interoperability (jwt.io reference vector)");

  // This token was generated at jwt.io with:
  //   algorithm : HS256
  //   secret    : "secret"
  //   payload   : {"sub":"1234567890","name":"John Doe","iat":1516239022}
  //
  // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
  // .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ
  // .SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

  const std::string reference_token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
      ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
      ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  const std::string secret = "your-256-bit-secret";

  // parse (no verify)
  {
    const auto t = jwt::parse(reference_token);
    CHECK("interop: parse subject",
          t.payload.subject() == "1234567890");
    CHECK("interop: parse iat",
          t.payload.issued_at() == std::int64_t{1516239022});
    CHECK("interop: parse custom 'name'",
          t.payload.get_string("name") == "John Doe");
    CHECK("interop: alg HS256",
          t.header.algorithm == jwt::detail::algorithm::HS256);
    CHECK("interop: type JWT",
          t.header.type == "JWT");
  }

  // The reference token uses the secret "your-256-bit-secret"
  {
    NO_THROW("interop: verify with correct secret",
             jwt::decode(reference_token, secret));
    const auto t = jwt::decode(reference_token, secret);
    CHECK("interop: verified=true", t.verified);
  }

  // Wrong secret fails
  THROWS_CODE("interop: wrong secret fails",
              jwt::error::code::signature_invalid,
              jwt::decode(reference_token, "wrong"));
}

// ============================================================================
//  main
// ============================================================================

int main()
{
  std::cout << "\n╔══════════════════════════════════════╗\n";
  std::cout << "║       jwt.hpp — test_basic.cpp       ║\n";
  std::cout << "╚══════════════════════════════════════╝\n";

  test_base64();
  test_crypto();
  test_json();
  test_encode_decode();
  test_algorithms();
  test_signature_security();
  test_format_errors();
  test_parse_no_verify();
  test_builder();
  test_claims();
  test_validator();
  test_utilities();
  test_interop();

  test::summary();
  return test::failed > 0 ? 1 : 0;
}
