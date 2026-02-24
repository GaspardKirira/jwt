/**
 * @file jwt.hpp
 * @brief Minimal JWT (HS256) implementation for modern C++.
 *
 * Header-only.
 * Depends on hmac (HMAC-SHA256).
 *
 * Supports:
 *  - HS256 signing
 *  - Token verification
 *  - Base64url encoding/decoding
 *
 * This is intentionally minimal and does not implement full JWT validation logic.
 *
 * MIT License
 */

#pragma once

#include <hmac/hmac.hpp>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace jwt
{

  // ============================================================
  // Base64url
  // ============================================================

  namespace detail
  {
    static constexpr char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    inline std::string base64url_encode(const std::uint8_t *data, std::size_t size)
    {
      std::string out;
      out.reserve(((size + 2) / 3) * 4);

      std::size_t i = 0;
      while (i + 3 <= size)
      {
        const std::uint32_t n =
            (data[i] << 16) |
            (data[i + 1] << 8) |
            (data[i + 2]);

        out.push_back(b64_table[(n >> 18) & 63]);
        out.push_back(b64_table[(n >> 12) & 63]);
        out.push_back(b64_table[(n >> 6) & 63]);
        out.push_back(b64_table[n & 63]);

        i += 3;
      }

      const std::size_t rem = size - i;

      if (rem == 1)
      {
        const std::uint32_t n = data[i] << 16;
        out.push_back(b64_table[(n >> 18) & 63]);
        out.push_back(b64_table[(n >> 12) & 63]);
      }
      else if (rem == 2)
      {
        const std::uint32_t n =
            (data[i] << 16) |
            (data[i + 1] << 8);

        out.push_back(b64_table[(n >> 18) & 63]);
        out.push_back(b64_table[(n >> 12) & 63]);
        out.push_back(b64_table[(n >> 6) & 63]);
      }

      return out;
    }

    inline int b64_index(char c)
    {
      if ('A' <= c && c <= 'Z')
        return c - 'A';
      if ('a' <= c && c <= 'z')
        return c - 'a' + 26;
      if ('0' <= c && c <= '9')
        return c - '0' + 52;
      if (c == '-')
        return 62;
      if (c == '_')
        return 63;
      return -1;
    }

    inline std::vector<std::uint8_t> base64url_decode(std::string_view s)
    {
      std::vector<std::uint8_t> out;
      std::uint32_t buffer = 0;
      int bits = 0;

      for (char c : s)
      {
        const int val = b64_index(c);
        if (val < 0)
          throw std::runtime_error("invalid base64url character");

        buffer = (buffer << 6) | static_cast<std::uint32_t>(val);
        bits += 6;

        if (bits >= 8)
        {
          bits -= 8;
          out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xff));
        }
      }

      return out;
    }

  } // namespace detail

  // ============================================================
  // Public API
  // ============================================================

  inline std::string encode(std::string_view payload_json, std::string_view secret)
  {
    const std::string header = R"({"alg":"HS256","typ":"JWT"})";

    const std::string header_b64 =
        detail::base64url_encode(reinterpret_cast<const std::uint8_t *>(header.data()), header.size());

    const std::string payload_b64 =
        detail::base64url_encode(reinterpret_cast<const std::uint8_t *>(payload_json.data()), payload_json.size());

    const std::string signing_input = header_b64 + "." + payload_b64;

    const auto signature_bytes =
        hmac::hmac_sha256_bytes(secret, signing_input);

    const std::string signature_b64 =
        detail::base64url_encode(signature_bytes.data(), signature_bytes.size());

    return signing_input + "." + signature_b64;
  }

  inline bool verify(std::string_view token, std::string_view secret)
  {
    const auto p1 = token.find('.');
    if (p1 == std::string_view::npos)
      return false;

    const auto p2 = token.find('.', p1 + 1);
    if (p2 == std::string_view::npos)
      return false;

    const std::string_view header_payload = token.substr(0, p2);
    const std::string_view signature_part = token.substr(p2 + 1);

    const auto expected_sig =
        hmac::hmac_sha256_bytes(secret, header_payload);

    const auto decoded_sig = detail::base64url_decode(signature_part);

    if (decoded_sig.size() != expected_sig.size())
      return false;

    for (std::size_t i = 0; i < expected_sig.size(); ++i)
    {
      if (decoded_sig[i] != expected_sig[i])
        return false;
    }

    return true;
  }

  inline std::string decode_without_verify(std::string_view token)
  {
    const auto p1 = token.find('.');
    if (p1 == std::string_view::npos)
      throw std::runtime_error("invalid jwt");

    const auto p2 = token.find('.', p1 + 1);
    if (p2 == std::string_view::npos)
      throw std::runtime_error("invalid jwt");

    const std::string_view payload_part =
        token.substr(p1 + 1, p2 - p1 - 1);

    const auto decoded = detail::base64url_decode(payload_part);

    return std::string(decoded.begin(), decoded.end());
  }

} // namespace jwt
