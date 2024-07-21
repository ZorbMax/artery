#ifndef PSEUDONYM_MESSAGE_HANDLER_H
#define PSEUDONYM_MESSAGE_HANDLER_H

#include "PseudonymMessage_m.h"
#include "vanetza/security/certificate.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <vanetza/security/backend_cryptopp.hpp>

class PseudonymMessageHandler
{
public:
    PseudonymMessageHandler(
        vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate);
    PseudonymMessage* createPseudonymMessage(vanetza::security::Certificate& pseudonym, vanetza::security::ecdsa256::PublicKey& public_key, std::string id);
    PseudonymMessage* createPseudonymMessage(vanetza::security::ecdsa256::PublicKey& public_key, std::string id);
    PseudonymMessage* createPseudonymMessage(vanetza::security::Certificate& pseudonym, std::string id);
    bool verifyPseudonymSignature(const PseudonymMessage* PseudonymMessage);

private:
    vanetza::security::BackendCryptoPP* mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mRootCert;

    vanetza::security::ecdsa256::PublicKey extractPublicKey(const vanetza::security::Certificate& certificate);
};

#endif  // V2V_MESSAGE_HANDLER_H
