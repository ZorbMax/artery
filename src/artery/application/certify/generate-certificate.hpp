#include <cryptopp/eccrypto.h>
#include <vanetza/security/certificate.hpp>

vanetza::security::Certificate GenerateCertificate(const HashedId8& root_hash, ecdsa256::PrivateKey& root_key, ecdsa256::PublicKey& key);

/* CERTIFY_COMMANDS_GENERATE_ROOT_HPP */
