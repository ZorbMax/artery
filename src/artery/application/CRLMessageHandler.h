#ifndef CRL_MESSAGE_HANDLER_H
#define CRL_MESSAGE_HANDLER_H

#include "CRLMessage_m.h"
#include "vanetza/security/certificate.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <vanetza/security/backend_cryptopp.hpp>

#include <vector>

class CRLMessageHandler
{
public:
    CRLMessageHandler(
        vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate);
    CRLMessage* createCRLMessage(const std::vector<vanetza::security::Certificate>& revokedCertificates);
    bool verifyCRLSignature(const CRLMessage* crlMessage);

private:
    vanetza::security::BackendCryptoPP* mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mRootCert;

    vanetza::security::ecdsa256::PublicKey extractPublicKey(const vanetza::security::Certificate& certificate);
};

#endif  // CRL_MESSAGE_HANDLER_H
