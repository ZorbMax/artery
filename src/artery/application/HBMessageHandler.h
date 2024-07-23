// HBMessageHandler.h
#ifndef HB_MESSAGE_HANDLER_H
#define HB_MESSAGE_HANDLER_H

#include "HBMessage_m.h"

#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>

#include <vector>

class HBMessageHandler
{
public:
    HBMessageHandler(
        vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate);

    HBMessage* createHeartbeatMessage(const std::vector<vanetza::security::HashedId8>& prl);
    bool verifyHeartbeatSignature(const HBMessage* heartbeatMessage);

private:
    vanetza::security::BackendCryptoPP* mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mRACertificate;

    vanetza::security::ecdsa256::PublicKey extractPublicKey(const vanetza::security::Certificate& certificate);
};

#endif  // HB_MESSAGE_HANDLER_H