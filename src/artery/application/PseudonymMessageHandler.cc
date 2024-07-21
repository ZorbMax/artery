#include "PseudonymMessageHandler.h"

#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/ecdsa256.hpp>

PseudonymMessageHandler::PseudonymMessageHandler(
    vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate) :
    mBackend(backend), mKeyPair(keyPair), mRootCert(certificate)
{
}

PseudonymMessage* PseudonymMessageHandler::createPseudonymMessage(vanetza::security::ecdsa256::PublicKey& public_key, std::string id)
{
    PseudonymMessage* pseudonymMessage = new PseudonymMessage("PseudonymMessage");


    pseudonymMessage->setTimestamp(omnetpp::simTime());
    pseudonymMessage->setCertificate(mRootCert);
    pseudonymMessage->setPublic_key(public_key);
    std::string payload = "This is a pseudonym message payload." + id;
    pseudonymMessage->setPayload(payload.c_str());

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(pseudonymMessage->getTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
        std::string payload = pseudonymMessage->getPayload();
        dataToSign.insert(dataToSign.end(), payload.begin(), payload.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        pseudonymMessage->setSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return pseudonymMessage;
}

PseudonymMessage* PseudonymMessageHandler::createPseudonymMessage(vanetza::security::Certificate& pseudonym, std::string id)
{
    PseudonymMessage* pseudonymMessage = new PseudonymMessage("PseudonymMessage");

    pseudonymMessage->setTimestamp(omnetpp::simTime());
    pseudonymMessage->setCertificate(mRootCert);
    pseudonymMessage->setPseudonym(pseudonym);
    std::string payload = "This is a pseudonym response." + id;
    pseudonymMessage->setPayload(payload.c_str());

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(pseudonymMessage->getTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
        std::string payload = pseudonymMessage->getPayload();
        dataToSign.insert(dataToSign.end(), payload.begin(), payload.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        pseudonymMessage->setSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return pseudonymMessage;
}

PseudonymMessage* PseudonymMessageHandler::createPseudonymMessage(
    vanetza::security::Certificate& pseudonym, vanetza::security::ecdsa256::PublicKey& public_key, std::string id)
{
    PseudonymMessage* pseudonymMessage = new PseudonymMessage("PseudonymMessage");

    pseudonymMessage->setTimestamp(omnetpp::simTime());
    pseudonymMessage->setCertificate(mRootCert);
    pseudonymMessage->setPseudonym(pseudonym);
    pseudonymMessage->setPublic_key(public_key);
    std::string payload = id;
    pseudonymMessage->setPayload(payload.c_str());

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(pseudonymMessage->getTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
        std::string payload = pseudonymMessage->getPayload();
        dataToSign.insert(dataToSign.end(), payload.begin(), payload.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        pseudonymMessage->setSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return pseudonymMessage;
}

bool PseudonymMessageHandler::verifyPseudonymSignature(const PseudonymMessage* pseudonymMessage)
{
    // std::cout << "Started pseudonym message signature verification..." << std::endl;

    vanetza::ByteBuffer dataToVerify;

    uint64_t timestamp = static_cast<uint64_t>(pseudonymMessage->getTimestamp().dbl() * 1e9);
    dataToVerify.insert(dataToVerify.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
    std::string payload = pseudonymMessage->getPayload();
    dataToVerify.insert(dataToVerify.end(), payload.begin(), payload.end());

    const vanetza::security::EcdsaSignature& signature = pseudonymMessage->getSignature();

    bool isValid = false;

    try {
        isValid = mBackend->verify_data(extractPublicKey(pseudonymMessage->getCertificate()), dataToVerify, signature);
        // std::cout << "Signature verification completed. Result: " << (isValid ? "Valid" : "Invalid") << std::endl;
    } catch (const std::runtime_error& e) {
        std::cout << "Error during signature verification: " << e.what() << std::endl;
    }

    return isValid;
}

vanetza::security::ecdsa256::PublicKey PseudonymMessageHandler::extractPublicKey(const vanetza::security::Certificate& certificate)
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
