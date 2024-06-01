// VehicleCRLService.cc
#include "VehicleCRLService.h"

#include "CRLMessage_m.h"
#include "RevocationAuthorityService.h"
#include "artery/networking/GeoNetPacket.h"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <arpa/inet.h>
#include <omnetpp.h>
#include <vanetza/btp/data_indication.hpp>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/btp/ports.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>

#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

Define_Module(artery::VehicleCRLService);

using namespace artery;
using namespace vanetza::security;
using namespace omnetpp;

namespace artery
{

void VehicleCRLService::initialize()
{
    ItsG5Service::initialize();

    mBackend.reset(new vanetza::security::BackendCryptoPP());
    std::cout << "Backend created: " << (mBackend ? "Yes" : "No") << std::endl;

    mLocalCRL.clear();
    std::cout << "VehicleCRLService initialized." << std::endl;
}

void VehicleCRLService::indicate(const vanetza::btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    // std::cout << "Received a message in VehicleCRLService on port " << ind.destination_port << " from channel " << net.channel << std::endl;

    if (packet) {
        // std::cout << "Packet name: " << packet->getName() << ", class: " << packet->getClassName() << std::endl;

        // Directly cast the received packet to CRLMessage
        CRLMessage* crlMessage = dynamic_cast<CRLMessage*>(packet);
        if (crlMessage) {
            std::cout << "Received a CRLMessage. Processing..." << crlMessage->getName() << std::endl;

            // Print the contents of the CRLMessage
            // std::cout << "Timestamp: " << crlMessage->getMTimestamp() << std::endl;

            // Print revoked certificates
            // unsigned int numRevokedCerts = crlMessage->getMRevokedCertificatesArraySize();
            // std::cout << "Number of revoked certificates: " << numRevokedCerts << std::endl;
            // for (unsigned int i = 0; i < numRevokedCerts; ++i) {
            //     vanetza::security::HashedId8& revokedCert = crlMessage->getMRevokedCertificates(i);
            // }

            // Call processing function
            handleCRLMessage(crlMessage);

            delete crlMessage;
        } else {
            std::cout << "Received packet is not a CRLMessage. Ignoring." << std::endl;
        }
    } else {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
    }
}


void VehicleCRLService::handleCRLMessage(CRLMessage* crlMessage)
{
    // Extract public key from the signer's certificate
    const vanetza::security::Certificate& signerCertificate = crlMessage->getMSignerCertificate();
    std::cout << "Got signer cert!" << std::endl;
    vanetza::security::ecdsa256::PublicKey publicKey = extractPublicKey(signerCertificate);
    std::cout << "Got public key!" << std::endl;

    // Verify the CRL signature
    if (!verifyCRLSignature(crlMessage, publicKey)) {
        std::cout << "CRL message signature verification failed." << std::endl;
        return;
    }

    // Update the local CRL with the revoked certificates
    unsigned int numRevokedCertificates = crlMessage->getMRevokedCertificatesArraySize();
    std::vector<vanetza::security::HashedId8> revokedCertificates;
    for (unsigned int i = 0; i < numRevokedCertificates; ++i) {
        revokedCertificates.push_back(crlMessage->getMRevokedCertificates(i));
    }
    updateLocalCRL(revokedCertificates);

    std::cout << "CRL message processed successfully." << std::endl;
}

bool VehicleCRLService::verifyCRLSignature(const CRLMessage* crlMessage, const vanetza::security::ecdsa256::PublicKey& publicKey)
{
    std::cout << "Started signature verification..." << std::endl;

    // Collect data to verify
    vanetza::ByteBuffer dataToVerify;

    // Add the timestamp
    uint64_t timestamp = static_cast<uint64_t>(crlMessage->getMTimestamp().dbl() * 1e9);  // Convert to nanoseconds
    dataToVerify.insert(dataToVerify.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));
    // std::cout << "Timestamp added: " << timestamp << std::endl;

    // Add revoked certificates hashes
    // std::cout << "Number of revoked certificates: " << crlMessage->getMRevokedCertificatesArraySize() << std::endl;
    for (size_t i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
        auto& hash = crlMessage->getMRevokedCertificates(i);
        dataToVerify.insert(dataToVerify.end(), hash.data(), hash.data() + hash.size());

        // std::cout << "Revoked certificate hash added: ";
        for (auto byte : hash) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << std::endl;
    }

    // Add the serialized signer certificate
    vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(crlMessage->getMSignerCertificate());
    dataToVerify.insert(dataToVerify.end(), serializedCert.begin(), serializedCert.end());
    // std::cout << "Serialized signer certificate added. Size: " << serializedCert.size() << std::endl;

    // Retrieve the signature from the message
    const vanetza::security::EcdsaSignature& signature = crlMessage->getMSignature();
    // std::cout << "Signature retrieved. S size: " << signature.s.size() << std::endl;

    // Print the signature values
    // std::cout << "Signature S: ";
    // for (auto byte : signature.s) {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    // }
    // std::cout << std::endl;

    bool isValid = false;

    try {
        // std::cout << "Calling verify_data with publicKey, dataToVerify, and signature..." << std::endl;
        isValid = mBackend->verify_data(publicKey, dataToVerify, signature);
        std::cout << "Signature verification completed. Result: " << (isValid ? "Valid" : "Invalid") << std::endl;
    } catch (const std::runtime_error& e) {
        std::cout << "Error during signature verification: " << e.what() << std::endl;
    }

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
    // std::cout << "Started extraction..." << std::endl;
    for (const auto& attribute : certificate.subject_attributes) {
        // std::cout << "Inspecting attribute..." << std::endl;

        if (auto verificationKey = boost::get<vanetza::security::VerificationKey>(&attribute)) {
            // std::cout << "Verification key present!" << std::endl;

            if (auto key = boost::get<vanetza::security::ecdsa_nistp256_with_sha256>(&verificationKey->key)) {
                // std::cout << "ECDSA NIST P256 key found!" << std::endl;

                const auto& publicKeyData = key->public_key;
                vanetza::security::ecdsa256::PublicKey publicKey;

                if (auto uncompressedPoint = boost::get<vanetza::security::Uncompressed>(&publicKeyData)) {
                    // std::cout << "Uncompressed point found!" << std::endl;

                    std::copy(uncompressedPoint->x.begin(), uncompressedPoint->x.end(), publicKey.x.begin());
                    std::copy(uncompressedPoint->y.begin(), uncompressedPoint->y.end(), publicKey.y.begin());

                    // Print the public key
                    // std::cout << "Public key (x): ";
                    // for (auto byte : publicKey.x) {
                    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
                    // }
                    // std::cout << std::endl;

                    // std::cout << "Public key (y): ";
                    // for (auto byte : publicKey.y) {
                    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
                    // }
                    // std::cout << std::endl;

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

    // std::cout << "Public key not found in the certificate." << std::endl;
    return vanetza::security::ecdsa256::PublicKey();
}


}  // namespace artery
