#include "util.hpp"
#include <array>
#include <iomanip>
#include <sstream>
#include <string.h>

std::string addr_len_str(uint32_t* addrlen)
{
    std::ostringstream ss;
    if (addrlen) {
        ss << *addrlen;
    } else {
        ss << "?";
    }
    return ss.str();
}

std::string ptrtohex(const void* p)
{
    std::ostringstream ss;
    ss << (p) ? p : "NULL";
    return ss.str();
}

std::string tohex(const uint8_t* buf, std::size_t length, size_t pad, bool ascii)
{
    static const char rgbDigits[] = "0123456789abcdef";
    std::size_t count = 0;
    std::stringstream out;
    for (std::size_t index = 0; length; length -= count, buf += count, index += count) {
        count = (length > 16) ? 16 : length;
        out << std::string(pad, ' ') << std::hex << std::setw(4) << std::setfill('0') << index
            << ": ";
        std::size_t i = 0;
        for (; i < count; i++) {
            out << rgbDigits[buf[i] >> 4];
            out << rgbDigits[buf[i] & 0x0f];
            out << ((i == 7) ? "  " : " ");
        }
        for (; i < 16; i++) {
            out << ((i == 7) ? "    " : "   ");
        }
        if (ascii) {
            out << "   ";
            for (i = 0; i < count; i++) {
                out << ((buf[i] < 32 || buf[i] > 126) ? "." : std::string(1, buf[i]));
            }
        }
        out << "\n";
    }
    return out.str();
}

std::string tohex_short(const void* buf, std::size_t length, size_t pad)
{
    static const char rgbDigits[] = "0123456789abcdef";
    std::stringstream out;
    out << std::string(pad, ' ');
    const unsigned char* pb = static_cast<const unsigned char*>(buf);
    for (size_t i = 0; i < length; i++) {
        out << rgbDigits[pb[i] >> 4];
        out << rgbDigits[pb[i] & 0x0f];
    }
    return out.str();
}
