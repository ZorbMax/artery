#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include "PublicKey.h"

// Serialize the PublicKey struct into a byte stream
void serializePublicKey(const vanetza::security::ecdsa256::PublicKey& key, uint8_t* buffer) {
    memcpy(buffer, key.x.data(), digest_octets);
    memcpy(buffer + digest_octets, key.y.data(), digest_octets);
}

// Deserialize a byte stream into a PublicKey struct
vanetza::security::ecdsa256::PublicKey deserializePublicKey(const uint8_t* buffer) {
    vanetza::security::ecdsa256::PublicKey key;
    memcpy(key.x.data(), buffer, digest_octets);
    memcpy(key.y.data(), buffer + digest_octets, digest_octets);
    return key;
}

// Combine a tag string and serialized data with a delimiter
std::string createPacket(const std::string& tag, const uint8_t* data) {
    return tag + "|" + std::string(reinterpret_cast<const char*>(data), dataSize);
}

// Parse a packet into a tag and serialized data
void parsePacket(const std::string& packet, std::string& tag, const uint8_t*& data) {
    size_t delimiterPos = packet.find("|");
    if (delimiterPos != std::string::npos) {
        tag = packet.substr(0, delimiterPos);
        data = reinterpret_cast<const uint8_t*>(packet.data() + delimiterPos + 1);
    }
}

// void serializeCertificate(const vanetza::security::Certificate cert, uint8_t* buffer) {
//        const void* cert_data = &cert;
//        memcpy(buffer, cert_data, sizeof(cert));
//        std::cout << buffer << std::endl;
//    }

// vanetza::security::Certificate deserializeCertificate(const uint8_t* buffer, size_t size) {
//        void* cert_data = malloc(size);
//        memcpy(cert_data, buffer, size);
//        vanetza::security::Certificate* cert_pointer = static_cast<vanetza::security::Certificate*>(cert_data);
//        std::cout << *cert_pointer << std::endl;
//        vanetza::security::Certificate cert = *cert_pointer;
//        return cert;
//}
