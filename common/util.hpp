#pragma once
#include <string>
#include <cstdint>

std::string addr_len_str(uint32_t *addrlen);
std::string ptrtohex(const void *p);
std::string tohex(const uint8_t * buf, std::size_t length, size_t pad, bool ascii);
std::string tohex_short(const void * buf, std::size_t length, size_t pad = 0);

template <typename T>
static std::string tohex_field(const T & field)
{
    return tohex_short(reinterpret_cast<const uint8_t *>(&field), sizeof(field));
}
