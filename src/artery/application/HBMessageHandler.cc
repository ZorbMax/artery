#include "HBMessageHandler.h"

#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>

#include <iostream>
#include <vector>

HBMessageHandler::HBMessageHandler(
    vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate) :
    mBackend(backend), mKeyPair(keyPair), mRACertificate(certificate)
{
}

HBMessage* HBMessageHandler::createHeartbeatMessage(const std::vector<vanetza::security::HashedId8>& prl)
{
    HBMessage* hbMessage = new HBMessage("Heartbeat");

    hbMessage->setTimestamp(omnetpp::simTime());
    hbMessage->setPRLArraySize(prl.size());

    for (size_t i = 0; i < prl.size(); ++i) {
        hbMessage->setPRL(i, prl[i]);
    }

    hbMessage->setMSignerCertificate(mRACertificate);

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(hbMessage->getTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

        for (size_t i = 0; i < hbMessage->getPRLArraySize(); ++i) {
            auto& hash = hbMessage->getPRL(i);
            dataToSign.insert(dataToSign.end(), hash.data(), hash.data() + hash.size());
        }

        vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(hbMessage->getMSignerCertificate());
        dataToSign.insert(dataToSign.end(), serializedCert.begin(), serializedCert.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        hbMessage->setMSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return hbMessage;
}

bool HBMessageHandler::verifyHeartbeatSignature(const HBMessage* hbMessage)
{
    vanetza::ByteBuffer dataToVerify;

    uint64_t timestamp = static_cast<uint64_t>(hbMessage->getMTimestamp().dbl() * 1e9);
    dataToVerify.insert(dataToVerify.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

    for (size_t i = 0; i < hbMessage->getPRLArraySize(); ++i) {
        auto& hash = hbMessage->getPRL(i);
        dataToVerify.insert(dataToVerify.end(), hash.data(), hash.data() + hash.size());
    }

    vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(hbMessage->getMSignerCertificate());
    dataToVerify.insert(dataToVerify.end(), serializedCert.begin(), serializedCert.end());

    const vanetza::security::EcdsaSignature& signature = hbMessage->getMSignature();

    bool isValid = false;
    try {
        isValid = mBackend->verify_data(extractPublicKey(hbMessage->getMSignerCertificate()), dataToVerify, signature);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error during signature verification: " << e.what() << std::endl;
    }

    return isValid;
}

vanetza::security::ecdsa256::PublicKey HBMessageHandler::extractPublicKey(const vanetza::security::Certificate& certificate)
{
    for (const auto& attribute : certificate.subject_attributes) {
        if (auto verificationKey = boost::get<vanetza::security::VerificationKey>(&attribute)) {
            if (auto key = boost::get<vanetza::security::ecdsa_nistp256_with_sha256>(&verificationKey->key)) {
                const auto& publicKeyData = key->public_key;
                vanetza::security::ecdsa256::PublicKey publicKey;

                if (auto uncompressedPoint = boost::get<vanetza::security::Uncompressed>(&publicKeyData)) {
                    std::copy(uncompressedPoint->x.begin(), uncompressedPoint->x.end(), publicKey.x.begin());
                    std::copy(uncompressedPoint->y.begin(), uncompressedPoint->y.end(), publicKey.y.begin());
                    return publicKey;
                } else {
                    std::cerr << "Public key is not uncompressed." << std::endl;
                }
            } else {
                std::cerr << "Verification key is not ECDSA NIST P256." << std::endl;
            }
        }
    }

    std::cerr << "Public key not found in the certificate." << std::endl;
    return vanetza::security::ecdsa256::PublicKey();
}