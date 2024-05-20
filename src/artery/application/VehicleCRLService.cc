#include "VehicleCRLService.h"
#include "CRLMessage.h"
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/btp/data_indication.hpp>
#include <omnetpp.h>
#include <memory>
#include <vector>

Define_Module(artery::VehicleCRLService);

namespace artery {

void VehicleCRLService::initialize()
{
    // Initialize the service
    ItsG5BaseService::initialize();

    // Create the security backend
    mBackend = vanetza::security::create_backend("backend_cryptopp");

    // Clear the local CRL (it will be updated when the first CRL message is received)
    mLocalCRL.clear();
}

void VehicleCRLService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet)
{
    Enter_Method("indicate");

    if (packet != nullptr) {
        std::string content = packet->getName();
        size_t pos = content.find("|");
        if (pos != std::string::npos) {
            std::string tag = content.substr(0, pos);
            std::string data = content.substr(pos + 1);

            if (tag == "CRLMessage") {
                auto crlMessage = dynamic_cast<CRLMessage*>(packet);
                if (crlMessage != nullptr) {
                    handleCRLMessage(crlMessage);
                }
            }
        }
    }
}

void VehicleCRLService::handleCRLMessage(CRLMessage* crlMessage)
{
    // Extract the signer's certificate (Revocation Authority's certificate) from the CRL message
    const auto& signerCertificate = crlMessage->getSignerCertificate();

    // Extract the public key from the signer's certificate
    vanetza::security::ecdsa256::PublicKey publicKey = extractPublicKey(signerCertificate);

    // Verify the signature of the CRL message
    if (!verifyCRLSignature(crlMessage, publicKey)) {
        EV_ERROR << "CRL message signature verification failed" << std::endl;
        return;
    }

    // Extract the revoked certificates from the CRL message
    const auto& revokedCertificates = crlMessage->getRevokedCertificates();

    // Update the local CRL with the revoked certificates
    updateLocalCRL(revokedCertificates);

    EV_INFO << "CRL message processed successfully. Local CRL updated." << std::endl;
}

bool VehicleCRLService::verifyCRLSignature(const CRLMessage* crlMessage, const vanetza::security::ecdsa256::PublicKey& publicKey)
{
    // Get the signature from the CRL message
    const auto& signature = crlMessage->getSignature();

    // Create a byte buffer from the CRL message content
    std::ostringstream stream;
    stream << crlMessage->getTimestamp();
    for (const auto& hashedId : crlMessage->getRevokedCertificates()) {
        stream.write(reinterpret_cast<const char*>(hashedId.data()), hashedId.size());
    }
    vanetza::ByteBuffer crlContent(stream.str().begin(), stream.str().end());

    // Verify the signature using the public key
    bool isValid = false;
    try {
        isValid = mBackend->verify_data(publicKey, crlContent, signature);
    } catch (const std::runtime_error& e) {
        EV_ERROR << "Error during signature verification: " << e.what() << std::endl;
    }
    return isValid;
}

void VehicleCRLService::updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates)
{
    // Merge the revoked certificates into the local CRL
    mLocalCRL.insert(mLocalCRL.end(), revokedCertificates.begin(), revokedCertificates.end());

    // Remove duplicates from the local CRL
    std::sort(mLocalCRL.begin(), mLocalCRL.end());
    mLocalCRL.erase(std::unique(mLocalCRL.begin(), mLocalCRL.end()), mLocalCRL.end());
}

bool VehicleCRLService::isRevoked(const vanetza::security::HashedId8& certificateHash)
{
    // Check if the certificate hash is present in the local CRL
    return std::binary_search(mLocalCRL.begin(), mLocalCRL.end(), certificateHash);
}

vanetza::security::ecdsa256::PublicKey VehicleCRLService::extractPublicKey(const vanetza::security::Certificate& certificate)
{
    // Iterate over the certificate's subject attributes to find the public key
    for (const auto& attribute : certificate.subject_attributes) {
        if (boost::get<vanetza::security::VerificationKey>(&attribute)) {
            const auto& verificationKey = boost::get<vanetza::security::VerificationKey>(attribute);
            if (boost::get<vanetza::security::ecdsa_nistp256_with_sha256>(&verificationKey.key)) {
                const auto& publicKeyData = boost::get<vanetza::security::ecdsa_nistp256_with_sha256>(verificationKey.key).public_key;
                vanetza::security::ecdsa256::PublicKey publicKey;
                if (boost::get<vanetza::security::Uncompressed>(&publicKeyData)) {
                    const auto& uncompressedPoint = boost::get<vanetza::security::Uncompressed>(publicKeyData);
                    std::copy(uncompressedPoint.x.begin(), uncompressedPoint.x.end(), publicKey.x.begin());
                    std::copy(uncompressedPoint.y.begin(), uncompressedPoint.y.end(), publicKey.y.begin());
                    return publicKey;
                }
            }
        }
    }

    // If the public key is not found, return an empty public key
    return vanetza::security::ecdsa256::PublicKey();
}

} // namespace artery