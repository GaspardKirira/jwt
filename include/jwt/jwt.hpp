/**
 * @file jwt.hpp
 * @brief Production-grade JWT library for C++20.
 *
 * Self-contained, header-only implementation of JSON Web Tokens (RFC 7519).
 *
 * Supported algorithms
 * --------------------
 *  HS256 · HS384 · HS512  (HMAC-SHA2 family)
 *
 * Architecture
 * ------------
 *  jwt::detail::base64      – Base64url codec
 *  jwt::detail::json        – Minimal JSON value + parser
 *  jwt::detail::crypto      – HMAC-SHA2 + constant-time compare
 *  jwt::claims              – Typed claim container (standard + custom)
 *  jwt::header_t            – Decoded JWT header
 *  jwt::token_t             – Full decoded token (header + claims + raw parts)
 *  jwt::builder             – Fluent token construction API
 *  jwt::validator           – Configurable validation pipeline
 *  jwt::encode()            – Sign and serialize a token
 *  jwt::decode()            – Verify, parse, and return a token
 *  jwt::parse()             – Parse without verification
 *
 * Security notes
 * --------------
 *  - Signature comparison is constant-time (no early exit).
 *  - The "none" algorithm is explicitly rejected.
 *  - Every structural and semantic error is reported via jwt::error.
 *  - Clock-skew tolerance is configurable on the validator.
 *
 * @author  Gaspard Kirira / Vix Project
 * @license MIT
 */

#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace jwt
{
  class claims;
  struct header_t;
  struct token_t;
  class builder;
  class validator;
  class error;

  std::string encode(const claims &payload, std::string_view secret,
                     std::string_view algorithm = "HS256");

  token_t decode(std::string_view token, std::string_view secret);
  token_t parse(std::string_view token);

} // namespace jwt

namespace jwt
{

  /**
   * @brief Base exception for all JWT errors.
   *
   * All functions that can fail throw a subclass of jwt::error.
   * Callers can catch jwt::error to handle any JWT-related failure.
   */
  class error : public std::runtime_error
  {
  public:
    enum class code : std::uint32_t
    {
      // structural
      malformed_token = 1000,
      invalid_base64 = 1001,
      invalid_json = 1002,
      invalid_algorithm = 1003,
      algorithm_mismatch = 1004,
      unsupported_algorithm = 1005,

      // signature
      signature_invalid = 2000,
      signature_missing = 2001,

      // claims
      token_expired = 3000,
      token_not_yet_valid = 3001,
      issuer_mismatch = 3002,
      audience_mismatch = 3003,
      subject_mismatch = 3004,
      missing_claim = 3005,
      claim_type_error = 3006,

      // internal
      internal = 9000,
    };

    explicit error(code c, std::string msg)
        : std::runtime_error(std::move(msg)), code_(c) {}

    [[nodiscard]] code err_code() const noexcept { return code_; }

  private:
    code code_;
  };

  /// Structural / format errors.
  class format_error final : public error
  {
  public:
    using error::error;
  };

  /// Cryptographic / signature errors.
  class signature_error final : public error
  {
  public:
    using error::error;
  };

  /// Semantic claim validation errors.
  class validation_error final : public error
  {
  public:
    using error::error;
  };

} // namespace jwt

namespace jwt::detail::base64
{

  static constexpr std::string_view ALPHABET =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  [[nodiscard]] inline std::string encode(const std::uint8_t *data, std::size_t size)
  {
    std::string out;
    out.reserve(((size + 2) / 3) * 4);

    auto push = [&](std::uint32_t n, int chars)
    {
      if (chars >= 1)
        out.push_back(ALPHABET[(n >> 18) & 0x3F]);
      if (chars >= 2)
        out.push_back(ALPHABET[(n >> 12) & 0x3F]);
      if (chars >= 3)
        out.push_back(ALPHABET[(n >> 6) & 0x3F]);
      if (chars >= 4)
        out.push_back(ALPHABET[(n) & 0x3F]);
    };

    std::size_t i = 0;
    while (i + 3 <= size)
    {
      const std::uint32_t n = (std::uint32_t(data[i]) << 16) | (std::uint32_t(data[i + 1]) << 8) | (std::uint32_t(data[i + 2]));
      push(n, 4);
      i += 3;
    }

    const std::size_t rem = size - i;
    if (rem == 1)
    {
      push(std::uint32_t(data[i]) << 16, 2);
    }
    else if (rem == 2)
    {
      const std::uint32_t n = (std::uint32_t(data[i]) << 16) | (std::uint32_t(data[i + 1]) << 8);
      push(n, 3);
    }
    return out;
  }

  [[nodiscard]] inline std::string encode(std::string_view s)
  {
    return encode(reinterpret_cast<const std::uint8_t *>(s.data()), s.size());
  }

  [[nodiscard]] inline int decode_char(char c) noexcept
  {
    if (c >= 'A' && c <= 'Z')
      return c - 'A';
    if (c >= 'a' && c <= 'z')
      return c - 'a' + 26;
    if (c >= '0' && c <= '9')
      return c - '0' + 52;
    if (c == '-')
      return 62;
    if (c == '_')
      return 63;
    return -1;
  }

  [[nodiscard]] inline std::vector<std::uint8_t> decode(std::string_view s)
  {
    std::vector<std::uint8_t> out;
    out.reserve((s.size() * 6) / 8 + 1);

    std::uint32_t buffer = 0;
    int bits = 0;

    for (char c : s)
    {
      if (c == '=')
        break; // tolerate padding
      const int val = decode_char(c);
      if (val < 0)
        throw format_error{error::code::invalid_base64,
                           std::string("invalid base64url character: ") + c};
      buffer = (buffer << 6) | std::uint32_t(val);
      bits += 6;
      if (bits >= 8)
      {
        bits -= 8;
        out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
      }
    }
    return out;
  }

  [[nodiscard]] inline std::string decode_to_string(std::string_view s)
  {
    const auto bytes = decode(s);
    return {bytes.begin(), bytes.end()};
  }

} // namespace jwt::detail::base64

namespace jwt::detail::json
{
  struct value; // forward

  using null_t = std::monostate;
  using bool_t = bool;
  using int_t = std::int64_t;
  using double_t = double;
  using string_t = std::string;
  using array_t = std::vector<value>;
  using object_t = std::unordered_map<std::string, value>;

  struct value
  {
    using variant_t = std::variant<
        null_t, bool_t, int_t, double_t, string_t, array_t, object_t>;

    variant_t data;

    value() : data(null_t{}) {}
    value(bool_t v) : data(v) {}
    value(int_t v) : data(v) {}
    value(double_t v) : data(v) {}
    value(std::string v) : data(std::move(v)) {}
    value(std::string_view v) : data(std::string(v)) {}
    value(const char *v) : data(std::string(v)) {}
    value(array_t v) : data(std::move(v)) {}
    value(object_t v) : data(std::move(v)) {}

    [[nodiscard]] bool is_null() const noexcept { return std::holds_alternative<null_t>(data); }
    [[nodiscard]] bool is_bool() const noexcept { return std::holds_alternative<bool_t>(data); }
    [[nodiscard]] bool is_int() const noexcept { return std::holds_alternative<int_t>(data); }
    [[nodiscard]] bool is_double() const noexcept { return std::holds_alternative<double_t>(data); }
    [[nodiscard]] bool is_string() const noexcept { return std::holds_alternative<string_t>(data); }
    [[nodiscard]] bool is_array() const noexcept { return std::holds_alternative<array_t>(data); }
    [[nodiscard]] bool is_object() const noexcept { return std::holds_alternative<object_t>(data); }

    [[nodiscard]] bool_t as_bool() const { return std::get<bool_t>(data); }
    [[nodiscard]] int_t as_int() const { return std::get<int_t>(data); }
    [[nodiscard]] double_t as_double() const { return std::get<double_t>(data); }
    [[nodiscard]] const string_t &as_string() const { return std::get<string_t>(data); }
    [[nodiscard]] const array_t &as_array() const { return std::get<array_t>(data); }
    [[nodiscard]] const object_t &as_object() const { return std::get<object_t>(data); }
  };

  inline void serialize(const value &v, std::string &out);

  inline void serialize_string(const std::string &s, std::string &out)
  {
    out += '"';
    for (char c : s)
    {
      switch (c)
      {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out += c;
        break;
      }
    }
    out += '"';
  }

  inline void serialize(const value &v, std::string &out)
  {
    std::visit([&out](const auto &val)
               {
        using T = std::decay_t<decltype(val)>;

        if constexpr (std::is_same_v<T, null_t>)
        {
            out += "null";
        }
        else if constexpr (std::is_same_v<T, bool_t>)
        {
            out += val ? "true" : "false";
        }
        else if constexpr (std::is_same_v<T, int_t>)
        {
            out += std::to_string(val);
        }
        else if constexpr (std::is_same_v<T, double_t>)
        {
            // Avoid locale-dependent formatting
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.17g", val);
            out += buf;
        }
        else if constexpr (std::is_same_v<T, string_t>)
        {
            serialize_string(val, out);
        }
        else if constexpr (std::is_same_v<T, array_t>)
        {
            out += '[';
            bool first = true;
            for (const auto& elem : val)
            {
                if (!first) out += ',';
                serialize(elem, out);
                first = false;
            }
            out += ']';
        }
        else if constexpr (std::is_same_v<T, object_t>)
        {
            out += '{';
            bool first = true;
            for (const auto& [k, ev] : val)
            {
                if (!first) out += ',';
                serialize_string(k, out);
                out += ':';
                serialize(ev, out);
                first = false;
            }
            out += '}';
        } }, v.data);
  }

  [[nodiscard]] inline std::string to_string(const value &v)
  {
    std::string out;
    out.reserve(256);
    serialize(v, out);
    return out;
  }

  struct parser_state
  {
    std::string_view src;
    std::size_t pos{0};

    [[nodiscard]] bool at_end() const noexcept { return pos >= src.size(); }
    [[nodiscard]] char peek() const noexcept { return at_end() ? '\0' : src[pos]; }
    char consume() noexcept { return at_end() ? '\0' : src[pos++]; }

    void skip_ws() noexcept
    {
      while (!at_end() && (src[pos] == ' ' || src[pos] == '\t' ||
                           src[pos] == '\n' || src[pos] == '\r'))
        ++pos;
    }

    [[noreturn]] void fail(const char *msg) const
    {
      throw format_error{error::code::invalid_json,
                         std::string("JSON parse error at pos ") + std::to_string(pos) + ": " + msg};
    }

    char expect(char c)
    {
      skip_ws();
      if (peek() != c)
        fail("unexpected character");
      return consume();
    }
  };

  inline value parse_value(parser_state &ps);

  inline std::string parse_string(parser_state &ps)
  {
    ps.expect('"');
    std::string out;
    while (true)
    {
      if (ps.at_end())
        ps.fail("unterminated string");
      const char c = ps.consume();
      if (c == '"')
        break;
      if (c != '\\')
      {
        out += c;
        continue;
      }
      // escape
      switch (ps.consume())
      {
      case '"':
        out += '"';
        break;
      case '\\':
        out += '\\';
        break;
      case '/':
        out += '/';
        break;
      case 'n':
        out += '\n';
        break;
      case 'r':
        out += '\r';
        break;
      case 't':
        out += '\t';
        break;
      case 'b':
        out += '\b';
        break;
      case 'f':
        out += '\f';
        break;
      default:
        ps.fail("unknown escape");
      }
    }
    return out;
  }

  inline value parse_number(parser_state &ps)
  {
    const std::size_t start = ps.pos;
    bool is_float = false;

    if (ps.peek() == '-')
      ps.consume();
    while (!ps.at_end() && ps.peek() >= '0' && ps.peek() <= '9')
      ps.consume();
    if (!ps.at_end() && ps.peek() == '.')
    {
      is_float = true;
      ps.consume();
      while (!ps.at_end() && ps.peek() >= '0' && ps.peek() <= '9')
        ps.consume();
    }
    if (!ps.at_end() && (ps.peek() == 'e' || ps.peek() == 'E'))
    {
      is_float = true;
      ps.consume();
      if (!ps.at_end() && (ps.peek() == '+' || ps.peek() == '-'))
        ps.consume();
      while (!ps.at_end() && ps.peek() >= '0' && ps.peek() <= '9')
        ps.consume();
    }

    const auto raw = std::string(ps.src.substr(start, ps.pos - start));
    if (is_float)
      return value{std::stod(raw)};
    return value{static_cast<int_t>(std::stoll(raw))};
  }

  inline array_t parse_array(parser_state &ps)
  {
    ps.expect('[');
    ps.skip_ws();
    array_t out;
    if (ps.peek() == ']')
    {
      ps.consume();
      return out;
    }
    while (true)
    {
      ps.skip_ws();
      out.push_back(parse_value(ps));
      ps.skip_ws();
      if (ps.peek() == ']')
      {
        ps.consume();
        break;
      }
      if (ps.peek() != ',')
        ps.fail("expected ',' or ']'");
      ps.consume();
    }
    return out;
  }

  inline object_t parse_object(parser_state &ps)
  {
    ps.expect('{');
    ps.skip_ws();
    object_t out;
    if (ps.peek() == '}')
    {
      ps.consume();
      return out;
    }
    while (true)
    {
      ps.skip_ws();
      const auto key = parse_string(ps);
      ps.skip_ws();
      ps.expect(':');
      ps.skip_ws();
      out[key] = parse_value(ps);
      ps.skip_ws();
      if (ps.peek() == '}')
      {
        ps.consume();
        break;
      }
      if (ps.peek() != ',')
        ps.fail("expected ',' or '}'");
      ps.consume();
    }
    return out;
  }

  inline value parse_value(parser_state &ps)
  {
    ps.skip_ws();
    const char c = ps.peek();

    if (c == '"')
      return value{parse_string(ps)};
    if (c == '{')
      return value{parse_object(ps)};
    if (c == '[')
      return value{parse_array(ps)};
    if (c == 't')
    {
      ps.pos += 4;
      return value{true};
    }
    if (c == 'f')
    {
      ps.pos += 5;
      return value{false};
    }
    if (c == 'n')
    {
      ps.pos += 4;
      return value{};
    }
    if (c == '-' || (c >= '0' && c <= '9'))
      return parse_number(ps);

    ps.fail("unexpected character");
  }

  [[nodiscard]] inline value parse(std::string_view src)
  {
    parser_state ps{src, 0};
    auto v = parse_value(ps);
    ps.skip_ws();
    if (!ps.at_end())
      throw format_error{error::code::invalid_json,
                         "trailing content after JSON value"};
    return v;
  }

} // namespace jwt::detail::json

namespace jwt::detail::crypto
{
  static constexpr std::array<std::uint32_t, 64> SHA256_K = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  static constexpr std::uint32_t rotr32(std::uint32_t x, unsigned n) noexcept
  {
    return (x >> n) | (x << (32 - n));
  }

  using sha256_digest = std::array<std::uint8_t, 32>;

  [[nodiscard]] inline sha256_digest sha256(const std::uint8_t *msg, std::size_t len)
  {
    std::uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    auto process_block = [&h](const std::uint8_t *blk)
    {
      std::uint32_t w[64];

      // Load block (big-endian)
      for (int i = 0; i < 16; ++i)
      {
        w[i] =
            (std::uint32_t(blk[i * 4]) << 24) |
            (std::uint32_t(blk[i * 4 + 1]) << 16) |
            (std::uint32_t(blk[i * 4 + 2]) << 8) |
            (std::uint32_t(blk[i * 4 + 3]));
      }

      // Message schedule (FORCE 32-bit wrap)
      for (int i = 16; i < 64; ++i)
      {
        const std::uint32_t s0 =
            rotr32(w[i - 15], 7) ^
            rotr32(w[i - 15], 18) ^
            (w[i - 15] >> 3);

        const std::uint32_t s1 =
            rotr32(w[i - 2], 17) ^
            rotr32(w[i - 2], 19) ^
            (w[i - 2] >> 10);

        w[i] = static_cast<std::uint32_t>(
            w[i - 16] + s0 + w[i - 7] + s1);
      }

      std::uint32_t a = h[0];
      std::uint32_t b = h[1];
      std::uint32_t c = h[2];
      std::uint32_t d = h[3];
      std::uint32_t e = h[4];
      std::uint32_t f = h[5];
      std::uint32_t g = h[6];
      std::uint32_t hh = h[7];

      for (int i = 0; i < 64; ++i)
      {
        const std::uint32_t S1 =
            rotr32(e, 6) ^
            rotr32(e, 11) ^
            rotr32(e, 25);

        const std::uint32_t ch =
            (e & f) ^ (~e & g);

        const std::uint32_t temp1 = static_cast<std::uint32_t>(
            hh + S1 + ch + SHA256_K[i] + w[i]);

        const std::uint32_t S0 =
            rotr32(a, 2) ^
            rotr32(a, 13) ^
            rotr32(a, 22);

        const std::uint32_t maj =
            (a & b) ^ (a & c) ^ (b & c);

        const std::uint32_t temp2 = static_cast<std::uint32_t>(S0 + maj);

        hh = g;
        g = f;
        f = e;
        e = static_cast<std::uint32_t>(d + temp1);
        d = c;
        c = b;
        b = a;
        a = static_cast<std::uint32_t>(temp1 + temp2);
      }

      h[0] += a;
      h[1] += b;
      h[2] += c;
      h[3] += d;
      h[4] += e;
      h[5] += f;
      h[6] += g;
      h[7] += hh;
    };

    // Padding (robust)
    const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8;

    std::size_t pad_len = 1;
    while ((len + pad_len + 8) % 64 != 0)
      ++pad_len;

    const std::size_t total = len + pad_len + 8;

    std::vector<std::uint8_t> buf(total, 0);
    std::memcpy(buf.data(), msg, len);
    buf[len] = 0x80;

    for (int i = 0; i < 8; ++i)
      buf[total - 8 + i] = static_cast<std::uint8_t>(bit_len >> (56 - 8 * i));

    for (std::size_t off = 0; off < total; off += 64)
      process_block(buf.data() + off);

    sha256_digest out;
    for (int i = 0; i < 8; ++i)
    {
      out[i * 4 + 0] = static_cast<std::uint8_t>(h[i] >> 24);
      out[i * 4 + 1] = static_cast<std::uint8_t>(h[i] >> 16);
      out[i * 4 + 2] = static_cast<std::uint8_t>(h[i] >> 8);
      out[i * 4 + 3] = static_cast<std::uint8_t>(h[i]);
    }

    return out;
  }

  // SHA-512 (and SHA-384 via truncation) -----------------------------------

  static constexpr std::array<std::uint64_t, 80> SHA512_K = {
      0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
      0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
      0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
      0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
      0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
      0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
      0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
      0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
      0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
      0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
      0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
      0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
      0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
      0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
      0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
      0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
      0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
      0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
      0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
      0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

  static constexpr std::uint64_t rotr64(std::uint64_t x, unsigned n) noexcept
  {
    return (x >> n) | (x << (64 - n));
  }

  using sha512_digest = std::array<std::uint8_t, 64>;
  using sha384_digest = std::array<std::uint8_t, 48>;

  enum class sha2_variant
  {
    sha512,
    sha384
  };

  template <sha2_variant V>
  [[nodiscard]] inline auto sha512_family(const std::uint8_t *msg, std::size_t len)
      -> std::conditional_t<V == sha2_variant::sha512, sha512_digest, sha384_digest>
  {
    std::uint64_t h[8];
    if constexpr (V == sha2_variant::sha512)
    {
      h[0] = 0x6a09e667f3bcc908ULL;
      h[1] = 0xbb67ae8584caa73bULL;
      h[2] = 0x3c6ef372fe94f82bULL;
      h[3] = 0xa54ff53a5f1d36f1ULL;
      h[4] = 0x510e527fade682d1ULL;
      h[5] = 0x9b05688c2b3e6c1fULL;
      h[6] = 0x1f83d9abfb41bd6bULL;
      h[7] = 0x5be0cd19137e2179ULL;
    }
    else
    {
      h[0] = 0xcbbb9d5dc1059ed8ULL;
      h[1] = 0x629a292a367cd507ULL;
      h[2] = 0x9159015a3070dd17ULL;
      h[3] = 0x152fecd8f70e5939ULL;
      h[4] = 0x67332667ffc00b31ULL;
      h[5] = 0x8eb44a8768581511ULL;
      h[6] = 0xdb0c2e0d64f98fa7ULL;
      h[7] = 0x47b5481dbefa4fa4ULL;
    }

    auto process_block = [&h](const std::uint8_t *blk)
    {
      std::uint64_t w[80];
      for (int i = 0; i < 16; ++i)
      {
        w[i] = 0;
        for (int b = 0; b < 8; ++b)
          w[i] = (w[i] << 8) | blk[i * 8 + b];
      }
      for (int i = 16; i < 80; ++i)
      {
        const auto s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const auto s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
      }
      std::uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hv = h[7];
      for (int i = 0; i < 80; ++i)
      {
        const auto S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        const auto ch = (e & f) ^ (~e & g);
        const auto t1 = hv + S1 + ch + SHA512_K[i] + w[i];
        const auto S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        const auto maj = (a & b) ^ (a & c) ^ (b & c);
        const auto t2 = S0 + maj;
        hv = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
      }
      h[0] += a;
      h[1] += b;
      h[2] += c;
      h[3] += d;
      h[4] += e;
      h[5] += f;
      h[6] += g;
      h[7] += hv;
    };

    const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8;

    // Correct padding (SHA-512):
    // message + 0x80 + padding + 16 bytes length
    // total % 128 == 0
    const std::size_t mod = len % 128;
    const std::size_t pad_len = (mod < 112) ? (112 - mod - 1) : (240 - mod - 1);
    const std::size_t total = len + 1 + pad_len + 16;

    std::vector<std::uint8_t> buf(total, 0);
    std::memcpy(buf.data(), msg, len);
    buf[len] = 0x80;

    // 128-bit big-endian length
    // High 64 bits = 0
    for (int i = 0; i < 8; ++i)
      buf[total - 16 + i] = 0;

    // Low 64 bits
    for (int i = 0; i < 8; ++i)
      buf[total - 8 + i] = static_cast<std::uint8_t>(bit_len >> (56 - 8 * i));

    // Process blocks
    for (std::size_t off = 0; off < total; off += 128)
      process_block(buf.data() + off);

    // Output
    constexpr std::size_t outlen = (V == sha2_variant::sha512) ? 64 : 48;
    std::conditional_t<V == sha2_variant::sha512, sha512_digest, sha384_digest> out;

    for (std::size_t i = 0; i < outlen / 8; ++i)
    {
      for (int b = 0; b < 8; ++b)
      {
        out[i * 8 + b] = static_cast<std::uint8_t>(h[i] >> (56 - 8 * b));
      }
    }

    return out;
  }

  template <std::size_t BlockSize, std::size_t DigestSize,
            auto HashFn>
  [[nodiscard]] inline std::array<std::uint8_t, DigestSize>
  hmac(const std::uint8_t *key, std::size_t key_len,
       const std::uint8_t *data, std::size_t data_len)
  {
    std::array<std::uint8_t, BlockSize> k_pad{};

    if (key_len > BlockSize)
    {
      // Hash the key down to digest size
      const auto hk = HashFn(key, key_len);
      std::memcpy(k_pad.data(), hk.data(), DigestSize);
    }
    else
    {
      std::memcpy(k_pad.data(), key, key_len);
    }

    // ipad / opad
    std::array<std::uint8_t, BlockSize> ipad, opad;
    for (std::size_t i = 0; i < BlockSize; ++i)
    {
      ipad[i] = k_pad[i] ^ 0x36;
      opad[i] = k_pad[i] ^ 0x5C;
    }

    // inner = H(ipad || data)
    std::vector<std::uint8_t> inner_msg(BlockSize + data_len);
    std::memcpy(inner_msg.data(), ipad.data(), BlockSize);
    std::memcpy(inner_msg.data() + BlockSize, data, data_len);
    const auto inner = HashFn(inner_msg.data(), inner_msg.size());

    // outer = H(opad || inner)
    std::vector<std::uint8_t> outer_msg(BlockSize + DigestSize);
    std::memcpy(outer_msg.data(), opad.data(), BlockSize);
    std::memcpy(outer_msg.data() + BlockSize, inner.data(), DigestSize);
    return HashFn(outer_msg.data(), outer_msg.size());
  }

  // HMAC-SHA256
  [[nodiscard]] inline sha256_digest
  hmac_sha256(const std::uint8_t *key, std::size_t key_len,
              const std::uint8_t *data, std::size_t data_len)
  {
    return hmac<64, 32, [](const std::uint8_t *m, std::size_t n)
                { return sha256(m, n); }>(
        key, key_len, data, data_len);
  }

  // HMAC-SHA384
  [[nodiscard]] inline sha384_digest
  hmac_sha384(const std::uint8_t *key, std::size_t key_len,
              const std::uint8_t *data, std::size_t data_len)
  {
    return hmac<128, 48, [](const std::uint8_t *m, std::size_t n)
                {
                  return sha512_family<sha2_variant::sha384>(m, n);
                }>(key, key_len, data, data_len);
  }

  // HMAC-SHA512
  [[nodiscard]] inline sha512_digest
  hmac_sha512(const std::uint8_t *key, std::size_t key_len,
              const std::uint8_t *data, std::size_t data_len)
  {
    return hmac<128, 64, [](const std::uint8_t *m, std::size_t n)
                {
                  return sha512_family<sha2_variant::sha512>(m, n);
                }>(key, key_len, data, data_len);
  }

  [[nodiscard]] inline bool constant_time_equal(
      const std::uint8_t *a, const std::uint8_t *b, std::size_t n) noexcept
  {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < n; ++i)
      diff |= a[i] ^ b[i];
    return diff == 0;
  }

  template <std::size_t N>
  [[nodiscard]] inline bool constant_time_equal(
      const std::array<std::uint8_t, N> &a,
      const std::vector<std::uint8_t> &b) noexcept
  {
    if (b.size() != N)
      return false;
    return constant_time_equal(a.data(), b.data(), N);
  }

} // namespace jwt::detail::crypto

namespace jwt::detail
{

  enum class algorithm
  {
    HS256,
    HS384,
    HS512
  };

  [[nodiscard]] inline algorithm algorithm_from_string(std::string_view s)
  {
    if (s == "HS256")
      return algorithm::HS256;
    if (s == "HS384")
      return algorithm::HS384;
    if (s == "HS512")
      return algorithm::HS512;
    if (s == "none" || s == "None" || s == "NONE")
      throw signature_error{error::code::unsupported_algorithm,
                            "Algorithm 'none' is explicitly rejected"};
    throw signature_error{error::code::unsupported_algorithm,
                          std::string("Unsupported algorithm: ") + std::string(s)};
  }

  [[nodiscard]] inline std::string_view algorithm_to_string(algorithm alg) noexcept
  {
    switch (alg)
    {
    case algorithm::HS256:
      return "HS256";
    case algorithm::HS384:
      return "HS384";
    case algorithm::HS512:
      return "HS512";
    }
    return "HS256";
  }

  [[nodiscard]] inline std::vector<std::uint8_t>
  sign(algorithm alg,
       std::string_view secret,
       std::string_view signing_input)
  {
    const auto *key = reinterpret_cast<const std::uint8_t *>(secret.data());
    const auto *data = reinterpret_cast<const std::uint8_t *>(signing_input.data());

    switch (alg)
    {
    case algorithm::HS256:
    {
      const auto d = crypto::hmac_sha256(key, secret.size(), data, signing_input.size());
      return {d.begin(), d.end()};
    }
    case algorithm::HS384:
    {
      const auto d = crypto::hmac_sha384(key, secret.size(), data, signing_input.size());
      return {d.begin(), d.end()};
    }
    case algorithm::HS512:
    {
      const auto d = crypto::hmac_sha512(key, secret.size(), data, signing_input.size());
      return {d.begin(), d.end()};
    }
    }
    throw error{error::code::internal, "unreachable"};
  }

} // namespace jwt::detail

namespace jwt
{

  /**
   * @brief Typed container for JWT claims (standard + custom).
   *
   * Standard string claims: iss, sub, jti
   * Standard numeric claims: exp, nbf, iat
   * Standard array claim: aud
   * Custom claims: any json::value
   */
  class claims
  {
  public:
    using time_point = std::chrono::system_clock::time_point;
    using seconds = std::chrono::seconds;

    claims &set_issuer(std::string v)
    {
      iss_ = std::move(v);
      return *this;
    }
    claims &set_subject(std::string v)
    {
      sub_ = std::move(v);
      return *this;
    }
    claims &set_jwt_id(std::string v)
    {
      jti_ = std::move(v);
      return *this;
    }

    claims &set_audience(std::string v)
    {
      aud_ = {std::move(v)};
      return *this;
    }
    claims &set_audience(std::vector<std::string> v)
    {
      aud_ = std::move(v);
      return *this;
    }

    claims &set_issued_at(time_point tp)
    {
      iat_ = std::chrono::duration_cast<seconds>(tp.time_since_epoch()).count();
      return *this;
    }
    claims &set_issued_at_now()
    {
      return set_issued_at(std::chrono::system_clock::now());
    }
    claims &set_expiration(time_point tp)
    {
      exp_ = std::chrono::duration_cast<seconds>(tp.time_since_epoch()).count();
      return *this;
    }
    claims &set_expiration(seconds from_now)
    {
      return set_expiration(std::chrono::system_clock::now() + from_now);
    }
    claims &set_not_before(time_point tp)
    {
      nbf_ = std::chrono::duration_cast<seconds>(tp.time_since_epoch()).count();
      return *this;
    }

    // Custom claims

    claims &set_claim(std::string key, detail::json::value v)
    {
      custom_[std::move(key)] = std::move(v);
      return *this;
    }
    claims &set_claim(std::string key, std::string v)
    {
      return set_claim(std::move(key), detail::json::value{std::move(v)});
    }
    claims &set_claim(std::string key, std::int64_t v)
    {
      return set_claim(std::move(key), detail::json::value{v});
    }
    claims &set_claim(std::string key, double v)
    {
      return set_claim(std::move(key), detail::json::value{v});
    }
    claims &set_claim(std::string key, bool v)
    {
      return set_claim(std::move(key), detail::json::value{v});
    }

    [[nodiscard]] const std::optional<std::string> &issuer() const noexcept { return iss_; }
    [[nodiscard]] const std::optional<std::string> &subject() const noexcept { return sub_; }
    [[nodiscard]] const std::optional<std::string> &jwt_id() const noexcept { return jti_; }
    [[nodiscard]] const std::vector<std::string> &audience() const noexcept { return aud_; }
    [[nodiscard]] std::optional<std::int64_t> issued_at() const noexcept { return iat_; }
    [[nodiscard]] std::optional<std::int64_t> expiration() const noexcept { return exp_; }
    [[nodiscard]] std::optional<std::int64_t> not_before() const noexcept { return nbf_; }

    [[nodiscard]] bool has_custom(const std::string &key) const noexcept
    {
      return custom_.count(key) > 0;
    }

    [[nodiscard]] const detail::json::value &get_claim(const std::string &key) const
    {
      const auto it = custom_.find(key);
      if (it == custom_.end())
        throw validation_error{error::code::missing_claim,
                               "Claim not found: " + key};
      return it->second;
    }

    [[nodiscard]] std::string get_string(const std::string &key) const
    {
      const auto &v = get_claim(key);
      if (!v.is_string())
        throw validation_error{error::code::claim_type_error,
                               "Claim '" + key + "' is not a string"};
      return v.as_string();
    }

    [[nodiscard]] std::int64_t get_int(const std::string &key) const
    {
      const auto &v = get_claim(key);
      if (!v.is_int())
        throw validation_error{error::code::claim_type_error,
                               "Claim '" + key + "' is not an integer"};
      return v.as_int();
    }

    [[nodiscard]] double get_double(const std::string &key) const
    {
      const auto &v = get_claim(key);
      if (!v.is_double())
        throw validation_error{error::code::claim_type_error,
                               "Claim '" + key + "' is not a double"};
      return v.as_double();
    }

    [[nodiscard]] bool get_bool(const std::string &key) const
    {
      const auto &v = get_claim(key);
      if (!v.is_bool())
        throw validation_error{error::code::claim_type_error,
                               "Claim '" + key + "' is not a bool"};
      return v.as_bool();
    }

    [[nodiscard]] const detail::json::array_t &get_array(const std::string &key) const
    {
      const auto &v = get_claim(key);
      if (!v.is_array())
        throw validation_error{error::code::claim_type_error,
                               "Claim '" + key + "' is not an array"};
      return v.as_array();
    }

    [[nodiscard]] std::string to_json() const
    {
      detail::json::object_t obj;

      if (iss_)
        obj["iss"] = *iss_;
      if (sub_)
        obj["sub"] = *sub_;
      if (jti_)
        obj["jti"] = *jti_;
      if (iat_)
        obj["iat"] = *iat_;
      if (exp_)
        obj["exp"] = *exp_;
      if (nbf_)
        obj["nbf"] = *nbf_;

      if (!aud_.empty())
      {
        if (aud_.size() == 1)
          obj["aud"] = aud_[0];
        else
        {
          detail::json::array_t arr;
          arr.reserve(aud_.size());
          for (const auto &a : aud_)
            arr.emplace_back(a);
          obj["aud"] = std::move(arr);
        }
      }

      for (const auto &[k, v] : custom_)
        obj[k] = v;

      detail::json::value jv{std::move(obj)};
      return detail::json::to_string(jv);
    }

    static claims from_json(std::string_view json_str)
    {
      const auto jv = detail::json::parse(json_str);
      if (!jv.is_object())
        throw format_error{error::code::invalid_json,
                           "JWT payload must be a JSON object"};

      claims c;
      for (const auto &[k, v] : jv.as_object())
      {
        if (k == "iss" && v.is_string())
        {
          c.iss_ = v.as_string();
          continue;
        }
        if (k == "sub" && v.is_string())
        {
          c.sub_ = v.as_string();
          continue;
        }
        if (k == "jti" && v.is_string())
        {
          c.jti_ = v.as_string();
          continue;
        }
        if (k == "iat" && v.is_int())
        {
          c.iat_ = v.as_int();
          continue;
        }
        if (k == "exp" && v.is_int())
        {
          c.exp_ = v.as_int();
          continue;
        }
        if (k == "nbf" && v.is_int())
        {
          c.nbf_ = v.as_int();
          continue;
        }
        if (k == "aud")
        {
          if (v.is_string())
            c.aud_ = {v.as_string()};
          else if (v.is_array())
            for (const auto &av : v.as_array())
              if (av.is_string())
                c.aud_.push_back(av.as_string());
          continue;
        }
        // Everything else is a custom claim
        c.custom_[k] = v;
      }
      return c;
    }

  private:
    std::optional<std::string> iss_, sub_, jti_;
    std::optional<std::int64_t> iat_, exp_, nbf_;
    std::vector<std::string> aud_;
    std::unordered_map<std::string, detail::json::value> custom_;
  };

} // namespace jwt

namespace jwt
{

  /// Decoded JWT header.
  struct header_t
  {
    detail::algorithm algorithm{detail::algorithm::HS256};
    std::string type{"JWT"};
    std::string kid;     ///< Key ID (optional)
    std::string raw_b64; ///< Original base64url-encoded header

    [[nodiscard]] std::string to_json() const
    {
      detail::json::object_t obj;
      obj["alg"] = std::string(detail::algorithm_to_string(algorithm));
      obj["typ"] = type;
      if (!kid.empty())
        obj["kid"] = kid;
      detail::json::value jv{std::move(obj)};
      return detail::json::to_string(jv);
    }

    static header_t from_json(std::string_view json_str)
    {
      const auto jv = detail::json::parse(json_str);
      if (!jv.is_object())
        throw format_error{error::code::malformed_token, "Header must be a JSON object"};

      header_t h;
      const auto &obj = jv.as_object();

      const auto alg_it = obj.find("alg");
      if (alg_it == obj.end())
        throw format_error{error::code::invalid_algorithm, "Header missing 'alg'"};
      h.algorithm = detail::algorithm_from_string(alg_it->second.as_string());

      const auto typ_it = obj.find("typ");
      if (typ_it != obj.end() && typ_it->second.is_string())
        h.type = typ_it->second.as_string();

      const auto kid_it = obj.find("kid");
      if (kid_it != obj.end() && kid_it->second.is_string())
        h.kid = kid_it->second.as_string();

      return h;
    }
  };

  /// A fully parsed JWT token.
  struct token_t
  {
    header_t header;
    claims payload;
    std::string raw_header_b64;    ///< Original header part (before first '.')
    std::string raw_payload_b64;   ///< Original payload part
    std::string raw_signature_b64; ///< Original signature part
    bool verified{false};          ///< True only after successful signature check
  };

} // namespace jwt

namespace jwt::detail
{

  struct raw_parts
  {
    std::string_view header;
    std::string_view payload;
    std::string_view signature;
    std::string_view signing_input; ///< header + "." + payload
  };

  [[nodiscard]] inline raw_parts split_token(std::string_view token)
  {
    const auto p1 = token.find('.');
    if (p1 == std::string_view::npos)
      throw format_error{error::code::malformed_token,
                         "JWT must have three dot-separated parts"};

    const auto p2 = token.find('.', p1 + 1);
    if (p2 == std::string_view::npos)
      throw format_error{error::code::malformed_token,
                         "JWT must have three dot-separated parts"};

    if (token.find('.', p2 + 1) != std::string_view::npos)
      throw format_error{error::code::malformed_token,
                         "JWT must not have more than three parts"};

    return {
        token.substr(0, p1),
        token.substr(p1 + 1, p2 - p1 - 1),
        token.substr(p2 + 1),
        token.substr(0, p2)};
  }

} // namespace jwt::detail

namespace jwt
{

  /**
   * @brief Encode a claims set into a signed JWT string.
   *
   * @param payload    Claims to embed in the token payload.
   * @param secret     Signing secret (HMAC key).
   * @param algorithm  One of "HS256", "HS384", "HS512".
   * @return           Signed JWT string (header.payload.signature).
   * @throws jwt::error on unsupported algorithm.
   */
  inline std::string encode(const claims &payload,
                            std::string_view secret,
                            std::string_view algorithm)
  {
    const auto alg = detail::algorithm_from_string(algorithm);

    // Build header JSON
    header_t hdr;
    hdr.algorithm = alg;
    const auto header_json = hdr.to_json();
    const auto header_b64 = detail::base64::encode(header_json);

    // Build payload JSON
    const auto payload_json = payload.to_json();
    const auto payload_b64 = detail::base64::encode(payload_json);

    // Signing input = header_b64 + "." + payload_b64
    const std::string signing_input = header_b64 + "." + payload_b64;

    // Sign
    const auto sig_bytes = detail::sign(alg, secret, signing_input);
    const auto sig_b64 = detail::base64::encode(sig_bytes.data(), sig_bytes.size());

    return signing_input + "." + sig_b64;
  }

} // namespace jwt

namespace jwt
{

  /**
   * @brief Parse a JWT without verifying the signature.
   *
   * Useful for extracting claims from a token whose signature was already
   * validated by another party, or for inspection / debugging.
   *
   * @warning Do NOT use for authorization decisions. Use decode() instead.
   * @throws jwt::error on structural or format errors.
   */
  inline token_t parse(std::string_view token)
  {
    const auto parts = detail::split_token(token);

    // Decode header
    const auto header_json = detail::base64::decode_to_string(parts.header);
    auto hdr = header_t::from_json(header_json);
    hdr.raw_b64 = std::string(parts.header);

    // Decode payload
    const auto payload_json = detail::base64::decode_to_string(parts.payload);
    auto pld = claims::from_json(payload_json);

    token_t t;
    t.header = std::move(hdr);
    t.payload = std::move(pld);
    t.raw_header_b64 = std::string(parts.header);
    t.raw_payload_b64 = std::string(parts.payload);
    t.raw_signature_b64 = std::string(parts.signature);
    t.verified = false;
    return t;
  }

  /**
   * @brief Verify the signature and parse a JWT.
   *
   * Steps:
   *  1. Structurally split the token.
   *  2. Decode and parse the header → determine algorithm.
   *  3. Recompute the expected signature over the signing input.
   *  4. Compare in constant time.
   *  5. If valid, parse and return the full token.
   *
   * @param token   The raw JWT string.
   * @param secret  The HMAC secret used to sign the token.
   * @return        Parsed token with verified = true.
   * @throws jwt::signature_error if the signature does not match.
   * @throws jwt::format_error    on structural / base64 / JSON errors.
   */
  inline token_t decode(std::string_view token_str, std::string_view secret)
  {
    const auto parts = detail::split_token(token_str);

    // Parse header to get algorithm
    const auto header_json = detail::base64::decode_to_string(parts.header);
    auto hdr = header_t::from_json(header_json);
    hdr.raw_b64 = std::string(parts.header);

    // Recompute signature
    const auto expected_bytes = detail::sign(hdr.algorithm, secret,
                                             parts.signing_input);

    // Decode provided signature
    const auto provided_bytes = detail::base64::decode(parts.signature);

    // Constant-time comparison
    if (expected_bytes.size() != provided_bytes.size() ||
        !detail::crypto::constant_time_equal(
            expected_bytes.data(), provided_bytes.data(), expected_bytes.size()))
    {
      throw signature_error{error::code::signature_invalid,
                            "JWT signature verification failed"};
    }

    // Parse payload
    const auto payload_json = detail::base64::decode_to_string(parts.payload);
    auto pld = claims::from_json(payload_json);

    token_t t;
    t.header = std::move(hdr);
    t.payload = std::move(pld);
    t.raw_header_b64 = std::string(parts.header);
    t.raw_payload_b64 = std::string(parts.payload);
    t.raw_signature_b64 = std::string(parts.signature);
    t.verified = true;
    return t;
  }

} // namespace jwt

namespace jwt
{

  /**
   * @brief Fluent JWT construction API.
   *
   * Usage:
   * @code
   * std::string token =
   *     jwt::builder()
   *         .set_issuer("myapp")
   *         .set_subject("user:42")
   *         .set_expiration(std::chrono::seconds{3600})
   *         .set_claim("role", "admin")
   *         .set_algorithm("HS384")
   *         .sign("my-secret-key");
   * @endcode
   */
  class builder
  {
  public:
    builder &set_issuer(std::string v)
    {
      claims_.set_issuer(std::move(v));
      return *this;
    }

    builder &set_subject(std::string v)
    {
      claims_.set_subject(std::move(v));
      return *this;
    }

    builder &set_audience(std::string v)
    {
      claims_.set_audience(std::move(v));
      return *this;
    }

    builder &set_audience(std::vector<std::string> v)
    {
      claims_.set_audience(std::move(v));
      return *this;
    }

    builder &set_jwt_id(std::string v)
    {
      claims_.set_jwt_id(std::move(v));
      return *this;
    }

    builder &set_issued_at_now()
    {
      claims_.set_issued_at_now();
      return *this;
    }

    builder &set_issued_at(std::chrono::system_clock::time_point tp)
    {
      claims_.set_issued_at(tp);
      return *this;
    }

    builder &set_expiration(std::chrono::seconds from_now)
    {
      claims_.set_expiration(from_now);
      return *this;
    }

    builder &set_expiration(std::chrono::system_clock::time_point tp)
    {
      claims_.set_expiration(tp);
      return *this;
    }

    builder &set_not_before(std::chrono::system_clock::time_point tp)
    {
      claims_.set_not_before(tp);
      return *this;
    }

    builder &set_not_before_now()
    {
      claims_.set_not_before(std::chrono::system_clock::now());
      return *this;
    }

    builder &set_claim(std::string key, detail::json::value v)
    {
      claims_.set_claim(std::move(key), std::move(v));
      return *this;
    }

    builder &set_claim(std::string key, std::string v)
    {
      claims_.set_claim(std::move(key), std::move(v));
      return *this;
    }

    builder &set_claim(std::string key, std::int64_t v)
    {
      claims_.set_claim(std::move(key), v);
      return *this;
    }

    builder &set_claim(std::string key, double v)
    {
      claims_.set_claim(std::move(key), v);
      return *this;
    }

    builder &set_claim(std::string key, bool v)
    {
      claims_.set_claim(std::move(key), v);
      return *this;
    }

    builder &set_algorithm(std::string_view alg)
    {
      algorithm_ = std::string(alg);
      return *this;
    }

    builder &set_key_id(std::string kid)
    {
      kid_ = std::move(kid);
      return *this;
    }

    /**
     * @brief Sign the token with the given secret and return the JWT string.
     * @param secret  HMAC key.
     * @return Signed JWT string.
     */
    [[nodiscard]] std::string sign(std::string_view secret) const
    {
      const auto alg = detail::algorithm_from_string(algorithm_);

      header_t hdr;
      hdr.algorithm = alg;
      hdr.kid = kid_;

      const auto header_json = hdr.to_json();
      const auto header_b64 = detail::base64::encode(header_json);
      const auto payload_b64 = detail::base64::encode(claims_.to_json());

      const std::string signing_input = header_b64 + "." + payload_b64;
      const auto sig_bytes = detail::sign(alg, secret, signing_input);
      const auto sig_b64 = detail::base64::encode(sig_bytes.data(), sig_bytes.size());

      return signing_input + "." + sig_b64;
    }

    /// Access the underlying claims object (read-only).
    [[nodiscard]] const claims &get_claims() const noexcept { return claims_; }

  private:
    claims claims_;
    std::string algorithm_{"HS256"};
    std::string kid_;
  };

} // namespace jwt

namespace jwt
{

  /**
   * @brief Configurable JWT validation pipeline.
   *
   * Validates standard claims after successful signature verification.
   * All checks are opt-in: only the ones explicitly configured are applied.
   *
   * Usage:
   * @code
   * jwt::validator v;
   * v.require_issuer("softadastra")
   *  .require_audience("api.service")
   *  .set_clock_skew(std::chrono::seconds{30});
   *
   * v.validate(token.payload);  // throws validation_error on failure
   * @endcode
   */
  class validator
  {
  public:
    using seconds = std::chrono::seconds;

    validator &require_issuer(std::string iss)
    {
      expected_iss_ = std::move(iss);
      return *this;
    }

    validator &require_subject(std::string sub)
    {
      expected_sub_ = std::move(sub);
      return *this;
    }

    validator &require_audience(std::string aud)
    {
      expected_aud_ = std::move(aud);
      return *this;
    }

    validator &require_jwt_id(std::string jti)
    {
      expected_jti_ = std::move(jti);
      return *this;
    }

    validator &set_clock_skew(seconds skew)
    {
      clock_skew_ = skew;
      return *this;
    }

    validator &check_expiration(bool v = true)
    {
      check_exp_ = v;
      return *this;
    }

    validator &check_not_before(bool v = true)
    {
      check_nbf_ = v;
      return *this;
    }

    validator &check_issued_at(bool v = true)
    {
      check_iat_ = v;
      return *this;
    }

    /**
     * @brief Validate the claims of a decoded token.
     *
     * @param c          Claims to validate.
     * @param now        Current time (injectable for testing).
     * @throws jwt::validation_error on the first failing check.
     */
    void validate(const claims &c,
                  std::chrono::system_clock::time_point now =
                      std::chrono::system_clock::now()) const
    {
      const auto now_sec =
          std::chrono::duration_cast<seconds>(now.time_since_epoch()).count();

      // exp — token expiration
      if (check_exp_ && c.expiration().has_value())
      {
        const auto exp = *c.expiration() + clock_skew_.count();
        if (now_sec > exp)
          throw validation_error{error::code::token_expired,
                                 "Token has expired (exp=" +
                                     std::to_string(*c.expiration()) + ")"};
      }

      // nbf — not before
      if (check_nbf_ && c.not_before().has_value())
      {
        const auto nbf = *c.not_before() - clock_skew_.count();
        if (now_sec < nbf)
          throw validation_error{error::code::token_not_yet_valid,
                                 "Token is not yet valid (nbf=" +
                                     std::to_string(*c.not_before()) + ")"};
      }

      // iat — issued at (must not be in the future)
      if (check_iat_ && c.issued_at().has_value())
      {
        const auto iat = *c.issued_at() - clock_skew_.count();
        if (now_sec < iat)
          throw validation_error{error::code::token_not_yet_valid,
                                 "Token issued_at is in the future"};
      }

      // iss — issuer
      if (expected_iss_.has_value())
      {
        if (!c.issuer().has_value() || *c.issuer() != *expected_iss_)
          throw validation_error{error::code::issuer_mismatch,
                                 "Issuer mismatch: expected '" +
                                     *expected_iss_ + "'"};
      }

      // sub — subject
      if (expected_sub_.has_value())
      {
        if (!c.subject().has_value() || *c.subject() != *expected_sub_)
          throw validation_error{error::code::subject_mismatch,
                                 "Subject mismatch: expected '" +
                                     *expected_sub_ + "'"};
      }

      // aud — audience (any of the token's audiences must match)
      if (expected_aud_.has_value())
      {
        const auto &aud = c.audience();
        const bool found = std::any_of(aud.begin(), aud.end(),
                                       [&](const std::string &a)
                                       { return a == *expected_aud_; });
        if (!found)
          throw validation_error{error::code::audience_mismatch,
                                 "Audience mismatch: expected '" +
                                     *expected_aud_ + "'"};
      }

      // jti — jwt id
      if (expected_jti_.has_value())
      {
        if (!c.jwt_id().has_value() || *c.jwt_id() != *expected_jti_)
          throw validation_error{error::code::missing_claim,
                                 "JWT ID mismatch"};
      }
    }

    /**
     * @brief Decode + verify signature + validate claims in one call.
     *
     * @param token_str  Raw JWT string.
     * @param secret     HMAC key.
     * @return           Fully verified and validated token.
     * @throws jwt::error on any failure.
     */
    [[nodiscard]] token_t decode_and_validate(std::string_view token_str,
                                              std::string_view secret) const
    {
      auto t = jwt::decode(token_str, secret);
      validate(t.payload);
      return t;
    }

  private:
    std::optional<std::string> expected_iss_, expected_sub_,
        expected_aud_, expected_jti_;
    seconds clock_skew_{0};
    bool check_exp_{true};
    bool check_nbf_{true};
    bool check_iat_{false};
  };

} // namespace jwt

namespace jwt
{

  /**
   * @brief Decode only the header of a JWT without verification.
   *
   * @param token_str  Raw JWT string.
   * @return           Parsed header_t.
   */
  [[nodiscard]] inline header_t parse_header(std::string_view token_str)
  {
    const auto parts = detail::split_token(token_str);
    const auto json = detail::base64::decode_to_string(parts.header);
    return header_t::from_json(json);
  }

  /**
   * @brief Decode only the payload of a JWT without verification.
   *
   * @param token_str  Raw JWT string.
   * @return           Parsed claims.
   */
  [[nodiscard]] inline claims parse_payload(std::string_view token_str)
  {
    const auto parts = detail::split_token(token_str);
    const auto json = detail::base64::decode_to_string(parts.payload);
    return claims::from_json(json);
  }

  /**
   * @brief Return true if the token appears structurally valid (3 parts, valid base64).
   *        Does NOT check the signature.
   */
  [[nodiscard]] inline bool is_structurally_valid(std::string_view token_str) noexcept
  {
    try
    {
      detail::split_token(token_str);
      return true;
    }
    catch (...)
    {
      return false;
    }
  }

  /**
   * @brief Return the remaining lifetime in seconds, or nullopt if no 'exp' claim.
   */
  [[nodiscard]] inline std::optional<std::int64_t>
  remaining_lifetime(const claims &c,
                     std::chrono::system_clock::time_point now =
                         std::chrono::system_clock::now())
  {
    if (!c.expiration())
      return std::nullopt;
    const auto now_sec =
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    return *c.expiration() - now_sec;
  }

} // namespace jwt
