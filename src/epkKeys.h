#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cctype>
#include <string>

#include <aes.hpp>

extern uint8_t epkKeys[][16];
extern size_t epkKeyCount;

struct EpkKey {
    size_t keySize;
    uint8_t* key;
    std::string comment;
};

void decryptAESecbAuto(uint8_t* data, size_t len, uint8_t* key, size_t key_size);
const uint8_t* tryFindAESkey(const uint8_t* data, size_t len, const uint8_t* magic, size_t magic_len, size_t offset);
EpkKey *tryFindAESkeyNew(const uint8_t* data, size_t len, const uint8_t* magic, size_t magic_len, size_t offset);