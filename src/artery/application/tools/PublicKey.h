#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/certificate.hpp>
#include <string>

constexpr size_t digest_octets = 32; // Example value, adjust as needed
constexpr size_t dataSize = digest_octets*2; // Example value, adjust as needed

void serializePublicKey(const vanetza::security::ecdsa256::PublicKey& key, uint8_t* buffer);

vanetza::security::ecdsa256::PublicKey deserializePublicKey(const uint8_t* buffer);

std::string createPacket(const std::string& tag, const uint8_t* data);

void parsePacket(const std::string& packet, std::string& tag, const uint8_t*& data);

//void serializeCertificate(const vanetza::security::Certificate cert, uint8_t* buffer);

//vanetza::security::Certificate deserializeCertificate(const uint8_t* buffer, size_t size);
