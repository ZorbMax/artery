#include "CRLMessageHandler.h"

#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/ecdsa256.hpp>

CRLMessageHandler::CRLMessageHandler(
    vanetza::security::BackendCryptoPP* backend, const vanetza::security::ecdsa256::KeyPair& keyPair, const vanetza::security::Certificate& certificate) :
    mBackend(backend), mKeyPair(keyPair), mRootCert(certificate)
{
}

CRLMessage* CRLMessageHandler::createCRLMessage(const std::vector<vanetza::security::Certificate>& revokedCertificates)
{
    CRLMessage* crlMessage = new CRLMessage("CRL");

    crlMessage->setMTimestamp(omnetpp::simTime());
    crlMessage->setMRevokedCertificatesArraySize(revokedCertificates.size());

    for (size_t i = 0; i < revokedCertificates.size(); ++i) {
        vanetza::security::HashedId8 hashedId = calculate_hash(revokedCertificates[i]);
        crlMessage->setMRevokedCertificates(i, hashedId);
    }

    crlMessage->setMSignerCertificate(mRootCert);

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(crlMessage->getMTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

        for (size_t i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
            auto& hash = crlMessage->getMRevokedCertificates(i);
            dataToSign.insert(dataToSign.end(), hash.data(), hash.data() + hash.size());
        }

        vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(crlMessage->getMSignerCertificate());
        dataToSign.insert(dataToSign.end(), serializedCert.begin(), serializedCert.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        crlMessage->setMSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return crlMessage;
}

bool CRLMessageHandler::verifyCRLSignature(const CRLMessage* crlMessage)
{
    // std::cout << "Started signature verification..." << std::endl;

    vanetza::ByteBuffer dataToVerify;

    uint64_t timestamp = static_cast<uint64_t>(crlMessage->getMTimestamp().dbl() * 1e9);
    dataToVerify.insert(dataToVerify.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

    for (size_t i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
        auto& hash = crlMessage->getMRevokedCertificates(i);
        dataToVerify.insert(dataToVerify.end(), hash.data(), hash.data() + hash.size());
    }

    vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(crlMessage->getMSignerCertificate());
    dataToVerify.insert(dataToVerify.end(), serializedCert.begin(), serializedCert.end());

    const vanetza::security::EcdsaSignature& signature = crlMessage->getMSignature();

    bool isValid = false;
    try {
        isValid = mBackend->verify_data(extractPublicKey(crlMessage->getMSignerCertificate()), dataToVerify, signature);
        // std::cout << "Signature verification completed. Result: " << (isValid ? "Valid" : "Invalid") << std::endl;
    } catch (const std::runtime_error& e) {
        // std::cout << "Error during signature verification: " << e.what() << std::endl;
    }

    return isValid;
}

vanetza::security::ecdsa256::PublicKey CRLMessageHandler::extractPublicKey(const vanetza::security::Certificate& certificate)
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
