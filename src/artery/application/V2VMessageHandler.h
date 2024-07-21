#ifndef V2V_MESSAGE_HANDLER_H
#define V2V_MESSAGE_HANDLER_H

#include "V2VMessage_m.h"
#include "vanetza/security/certificate.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <vanetza/security/backend_cryptopp.hpp>

class V2VMessageHandler
{
public:
    V2VMessageHandler(
        vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate);
    V2VMessage* createV2VMessage(const std::string& message);
    bool verifyV2VSignature(const V2VMessage* v2vMessage);

private:
    vanetza::security::BackendCryptoPP* mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mRootCert;

    vanetza::security::ecdsa256::PublicKey extractPublicKey(const vanetza::security::Certificate& certificate);
};

#endif  // V2V_MESSAGE_HANDLER_H
