#include "epkKeys.h"
#include "util.h"
#include <string>
#include <fstream>

void decryptAESecbAuto(uint8_t* data, size_t len, uint8_t* key, size_t key_size) {
    struct AES_ctx ctx;

    if (key_size == AES_KEY_128) {
        AES_init_ctx(&ctx, key, AES_KEY_128);
    } else if (key_size == AES_KEY_256) {
        AES_init_ctx(&ctx, key, AES_KEY_256);
    } else {
        // ?
    }

    size_t blocks = len / 16;

    for (size_t i = 0; i < blocks; i++) {
        AES_ECB_decrypt(&ctx, data + (i * 16));
    }

    //unaligned bytes are left plain, this is EPK behaviour.
}

static uint8_t hexToint(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return 0; //?
}

static std::vector<uint8_t> hexStrToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = (hexToint(hex[i]) << 4) | hexToint(hex[i + 1]);
        bytes.push_back(byte);
    }
    return bytes;
}

EpkKey *tryFindAESkeyNew(const uint8_t* data, size_t len, const uint8_t* magic, size_t magic_len, size_t offset) {
    if (offset + magic_len > len) {
        return nullptr;
    }
    std::vector<uint8_t> buf(len);

    std::wstring dir = getDLLlocation();
    DBG_LOG("[epkKeys] dll loc : %ls\n", dir.c_str());

    std::wstring keyFilePath = dir + L"\\AES.key";
    DBG_LOG("[epkKeys] open keyfile : %ls\n", keyFilePath.c_str());

    std::ifstream keyFile(keyFilePath);
    if (!keyFile.is_open()) {
        DBG_LOG("[epkKeys] fail to open aes key file\n");
        return nullptr;
    }

    std::string line;

    while (std::getline(keyFile, line)) {
        DBG_LOG("[epkKeys] LINE = %s\n", line.c_str());

        if (line.empty() || (line[0] == '#') || (line[0] == '\n') || (line[0] == '\r') || (line[0] == '\0')) {
            //comment or empty line
            continue;
        }

        std::string hexPart;
        std::string commentPart;

        size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            hexPart = line.substr(0, commentPos);
            commentPart = line.substr(commentPos + 1); //no #
        } else {
            hexPart = line.substr(0);
        }

        size_t hexStp = hexPart.find_last_not_of(" \t\r\n");
        if (hexStp == std::string::npos) {
            continue;
        }
        hexPart = hexPart.substr(0, hexStp + 1);
        commentPart = commentPart.empty() ? hexPart : commentPart; //if no comment use the hex repesentation of key

        DBG_LOG("[epkKeys] hex -> %s\n", hexPart.c_str());

        std::vector<uint8_t> key = hexStrToBytes(hexPart);

        uint8_t* key_data = key.data();
        size_t key_size = key.size();

        DBG_LOG("[epkKeys] key size -> %zu\n", key_size);
        DBG_LOG("[epkKeys] key -> ");
        for (int i = 0; i < key_size; i++) {
            DBG_LOG("%02X", key_data[i]);
        }
        DBG_LOG("\n");

        if (key_size == AES_KEY_128 || key_size == AES_KEY_256) {
            memcpy(buf.data(), data, len);

            decryptAESecbAuto(buf.data(), len, key_data, key_size);

            if (memcmp(buf.data() + offset, magic, magic_len) == 0) {
                DBG_LOG("[epkKeys] ^^^ SUCCESS KEY\n");
                EpkKey* keyE = new EpkKey();
                keyE->key = new uint8_t[key_size];
                memcpy(keyE->key, key_data, key_size);
                keyE->keySize = key_size;
                keyE->comment = commentPart;
                return keyE;
            }

        } else {
            DBG_LOG("[epkKeys] fail key size\n");
            continue;
        }

    }

    return nullptr;
}

