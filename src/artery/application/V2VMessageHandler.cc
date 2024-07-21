#include "V2VMessageHandler.h"

#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/ecdsa256.hpp>

V2VMessageHandler::V2VMessageHandler(
    vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate) :
    mBackend(backend), mKeyPair(keyPair), mRootCert(certificate)
{
}

V2VMessage* V2VMessageHandler::createV2VMessage(const std::string& payload)
{
    V2VMessage* v2vMessage = new V2VMessage("V2VMessage");

    v2vMessage->setTimestamp(omnetpp::simTime());
    v2vMessage->setCertificate(mRootCert);
    v2vMessage->setPayload(payload.c_str());

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(v2vMessage->getTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
        std::string payload = v2vMessage->getPayload();
        dataToSign.insert(dataToSign.end(), payload.begin(), payload.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        v2vMessage->setSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return v2vMessage;
}

bool V2VMessageHandler::verifyV2VSignature(const V2VMessage* v2vMessage)
{
    //std::cout << "Started V2V message signature verification..." << std::endl;

    vanetza::ByteBuffer dataToVerify;

    uint64_t timestamp = static_cast<uint64_t>(v2vMessage->getTimestamp().dbl() * 1e9);
    dataToVerify.insert(dataToVerify.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
    std::string payload = v2vMessage->getPayload();
    dataToVerify.insert(dataToVerify.end(), payload.begin(), payload.end());

    const vanetza::security::EcdsaSignature& signature = v2vMessage->getSignature();

    bool isValid = false;
    try {
        isValid = mBackend->verify_data(extractPublicKey(v2vMessage->getCertificate()), dataToVerify, signature);
        //std::cout << "Signature verification completed. Result: " << (isValid ? "Valid" : "Invalid") << std::endl;
    } catch (const std::runtime_error& e) {
        std::cout << "Error during signature verification: " << e.what() << std::endl;
    }

    return isValid;
}

vanetza::security::ecdsa256::PublicKey V2VMessageHandler::extractPublicKey(const vanetza::security::Certificate& certificate)
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
                    std::cout << "Public key is not uncompressed." << std::endl;
                }
            } else {
                std::cout << "Verification key is not ECDSA NIST P256." << std::endl;
            }
        } else {
            std::cout << "Attribute is not a verification key." << std::endl;
        }
    }

    std::cout << "Public key not found in the certificate." << std::endl;
    return vanetza::security::ecdsa256::PublicKey();
}
