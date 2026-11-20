#pragma once

#include "schannel_tls_stream.h"
#include <optional>

namespace proxy
{
    // The caller has already authenticated the TLS peer. Do not include credentials or
    // response headers in diagnostics, including on a 407.
    inline bool https_connect(schannel_tls_stream& stream, const std::string& authority,
        const std::optional<std::string>& username, const std::optional<std::string>& password,
        std::string& error)
    {
        std::string request = "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n";
        if (username && password)
        {
            const auto credentials = *username + ":" + *password;
            const auto size = static_cast<DWORD>(credentials.size());
            const auto* bytes = reinterpret_cast<const BYTE*>(credentials.data());
            constexpr DWORD flags = CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF;
            DWORD length = 0;
            if (!CryptBinaryToStringA(bytes, size, flags, nullptr, &length))
            {
                error = "Could not encode Basic credentials.";
                return false;
            }
            std::string encoded(length, '\0');
            if (!CryptBinaryToStringA(bytes, size, flags, encoded.data(), &length))
            {
                error = "Could not encode Basic credentials.";
                return false;
            }
            request += "Proxy-Authorization: Basic ";
            request.append(encoded.data(), length);
            request += "\r\n";
        }
        request += "\r\n";
        if (!stream.send_all(request.data(), static_cast<int>(request.size())))
        {
            error = stream.last_error();
            return false;
        }

        // Allow a bounded number of informational responses before the final status.
        for (int i = 0; i < 8; ++i)
        {
            std::string headers;
            if (!stream.recv_http_headers(headers))
            {
                error = stream.last_error();
                return false;
            }
            if ((headers.compare(0, 9, "HTTP/1.1 ") != 0 && headers.compare(0, 9, "HTTP/1.0 ") != 0) ||
                headers.size() < 14 || headers.find_first_not_of("0123456789", 9) != 12 ||
                (headers[12] != ' ' && headers.compare(12, 2, "\r\n") != 0))
            {
                error = "Malformed HTTP CONNECT response.";
                return false;
            }
            const auto status = headers.substr(9, 3);
            if (status[0] == '2') return true;
            if (status[0] == '1' && status != "101") continue;
            error = status == "407" ? "HTTPS proxy rejected Basic authentication (407)." :
                "HTTPS proxy rejected CONNECT (HTTP " + status + ").";
            return false;
        }
        error = "Too many informational responses to CONNECT.";
        return false;
    }
}
