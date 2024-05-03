#include <cryptopp/eccrypto.h>
#include <cryptopp/files.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/sha.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/basic_elements.hpp>

using namespace CryptoPP;
using namespace vanetza::security;

ecdsa256::KeyPair GenerateKey();
/* CERTIFY_COMMANDS_GENERATE_KEY_HPP */
