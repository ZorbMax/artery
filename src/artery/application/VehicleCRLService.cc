// VehicleCRLService.cc
#include "VehicleCRLService.h"

#include "CRLMessage.h"

#include <omnetpp.h>
#include <vanetza/btp/data_indication.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/public_key.hpp>

#include <memory>
#include <vector>

Define_Module(artery::VehicleCRLService);

namespace artery
{

void VehicleCRLService::initialize()
{
    ItsG5BaseService::initialize();
    mBackend = vanetza::security::create_backend("backend_cryptopp");
    mLocalCRL.clear();
    std::cout << "VehicleCRLService initialized." << std::endl;
}

void VehicleCRLService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet)
{
    Enter_Method("indicate");

    std::cout << "Received a message in VehicleCRLService!" << std::endl;

    if (packet != nullptr) {
        auto crlMessage = dynamic_cast<CRLMessage*>(packet);
        if (crlMessage != nullptr) {
            std::cout << "Received a CRLMessage. Processing..." << std::endl;
            handleCRLMessage(crlMessage);
        } else {
            std::cout << "Received packet is not a CRLMessage. Ignoring." << std::endl;
        }
    } else {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
    }
}

void VehicleCRLService::handleCRLMessage(CRLMessage* crlMessage)
{
    const auto& signerCertificate = crlMessage->getSignerCertificate();
    vanetza::security::ecdsa256::PublicKey publicKey = extractPublicKey(signerCertificate);

    if (!verifyCRLSignature(crlMessage, publicKey)) {
        std::cout << "CRL message signature verification failed." << std::endl;
        return;
    }

    const auto& revokedCertificates = crlMessage->getRevokedCertificates();
    updateLocalCRL(revokedCertificates);

    std::cout << "CRL message processed successfully. Local CRL updated." << std::endl;
}

bool VehicleCRLService::verifyCRLSignature(const CRLMessage* crlMessage, const vanetza::security::ecdsa256::PublicKey& publicKey)
{
    std::string serializedPayload = crlMessage->serializePayload();
    vanetza::ByteBuffer crlContent(serializedPayload.begin(), serializedPayload.end());
    const auto& signature = crlMessage->getSignature();
    bool isValid = false;

    try {
        isValid = mBackend->verify_data(publicKey, crlContent, signature);
    } catch (const std::runtime_error& e) {
        std::cout << "Error during signature verification: " << e.what() << std::endl;
    }

    std::cout << "CRL signature verification result: " << (isValid ? "Valid" : "Invalid") << std::endl;

    return isValid;
}

void VehicleCRLService::updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates)
{
    mLocalCRL.insert(mLocalCRL.end(), revokedCertificates.begin(), revokedCertificates.end());
    std::sort(mLocalCRL.begin(), mLocalCRL.end());
    mLocalCRL.erase(std::unique(mLocalCRL.begin(), mLocalCRL.end()), mLocalCRL.end());

    std::cout << "Local CRL updated. Current size: " << mLocalCRL.size() << std::endl;
}

bool VehicleCRLService::isRevoked(const vanetza::security::HashedId8& certificateHash)
{
    return std::binary_search(mLocalCRL.begin(), mLocalCRL.end(), certificateHash);
}

vanetza::security::ecdsa256::PublicKey VehicleCRLService::extractPublicKey(const vanetza::security::Certificate& certificate)
{
    for (const auto& attribute : certificate.subject_attributes) {
        if (auto verificationKey = boost::get<vanetza::security::VerificationKey>(&attribute)) {
            if (auto key = boost::get<vanetza::security::ecdsa_nistp256_with_sha256>(&verificationKey->key)) {
                const auto& publicKeyData = key->public_key;
                vanetza::security::ecdsa256::PublicKey publicKey;
                if (auto uncompressedPoint = boost::get<vanetza::security::Uncompressed>(&publicKeyData)) {
                    std::copy(uncompressedPoint->x.begin(), uncompressedPoint->x.end(), publicKey.x.begin());
                    std::copy(uncompressedPoint->y.begin(), uncompressedPoint->y.end(), publicKey.y.begin());
                    std::cout << "Public key extracted successfully." << std::endl;
                    return publicKey;
                }
            }
        }
    }

    EV_WARN << "Public key not found in the certificate." << std::endl;
    return vanetza::security::ecdsa256::PublicKey();
}

}  // namespace artery
