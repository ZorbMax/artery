#include "RevocationAuthorityService.h"

#include "CRLMessage.h"
#include "artery/networking/GeoNetPacket.h"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <omnetpp.h>
#include <vanetza/btp/data_request.hpp>
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

using namespace artery;
using namespace vanetza::security;

Define_Module(RevocationAuthorityService)

void RevocationAuthorityService::initialize()
{
    ItsG5BaseService::initialize();

    mBackend.reset(new vanetza::security::BackendCryptoPP());
    std::cout << "Backend created: " << (mBackend ? "Yes" : "No") << std::endl;

    if (mBackend) {
        mKeyPair = mBackend->generate_key_pair();
        std::cout << "Key pair generated successfully." << std::endl;

        // Generate the self-signed certificate using the GenerateRoot function
        mSignedCert = GenerateRoot(mKeyPair);
        std::cout << "Revocation Authority certificate signed and stored successfully." << std::endl;
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    mCrlGenInterval = 5.0;

    // For testing purposes, generate and distribute the CRL immediately
    std::vector<vanetza::security::Certificate> revokedCertificates;
    CRLMessage* signedCRLMessage = createAndSignCRL(revokedCertificates);
    broadcastCRLMessage(signedCRLMessage);
}

CRLMessage* RevocationAuthorityService::createAndSignCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates)
{
    // Step 1: Create a new CRLMessage object
    CRLMessage* crlMessage = new CRLMessage("CRL");

    // Step 2: Set the timestamp of the CRLMessage
    crlMessage->setTimestamp(omnetpp::simTime());

    // Step 3: Create a new vector to store the revoked certificate hashes
    std::vector<vanetza::security::HashedId8> revokedCertHashes;

    // Step 4: Iterate over the revoked certificates and add their hashes to the vector
    for (const auto& cert : revokedCertificates) {
        vanetza::security::HashedId8 hashedId = vanetza::security::calculate_hash(cert);
        revokedCertHashes.push_back(hashedId);
    }

    // Step 5: Set the revoked certificate hashes in the CRLMessage object
    crlMessage->setRevokedCertificates(revokedCertHashes);

    // Step 6: Set the signer's certificate in the CRLMessage object
    crlMessage->setSignerCertificate(mSignedCert);

    // Print the contents of the CRLMessage object before serialization
    std::cout << "CRLMessage contents before serialization:" << std::endl;
    std::cout << "Timestamp: " << crlMessage->getTimestamp() << std::endl;
    std::cout << "Revoked certificate count: " << crlMessage->getRevokedCertificates().size() << std::endl;
    std::cout << "Signer certificate subject name: ";
    for (const auto& byte : crlMessage->getSignerCertificate().subject_info.subject_name) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;

    // Step 7: Create the signature for the CRLMessage
    if (mBackend) {
        std::ostringstream crlStream;
        vanetza::OutputArchive archive(crlStream);
        std::cout << "BEFORE SERIAL" << std::endl;
        serialize(archive, *crlMessage);
        std::cout << "AFTER SERIAL" << std::endl;
        vanetza::ByteBuffer crlBuffer(crlStream.str().begin(), crlStream.str().end());
        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, crlBuffer);
        // Step 8: Set the signature in the CRLMessage object
        crlMessage->setSignature(ecdsaSignature);

        std::cout << "CRL Signature S size: " << ecdsaSignature.s.size() << std::endl;
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return crlMessage;
}

void RevocationAuthorityService::broadcastCRLMessage(CRLMessage* signedCRLMessage)
{
    Enter_Method("broadcastCRLMessage");

    using namespace vanetza;
    btp::DataRequestB request;
    request.destination_port = host_cast<uint16_t>(0x00FF);
    request.gn.its_aid = aid::CRL;
    request.gn.transport_type = geonet::TransportType::SHB;
    request.gn.maximum_lifetime = geonet::Lifetime{geonet::Lifetime::Base::One_Second, 1};
    request.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
    request.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;

    using CrlByteBuffer = convertible::byte_buffer_impl<CRLMessage>;
    std::unique_ptr<geonet::DownPacket> payload{new geonet::DownPacket()};
    std::unique_ptr<CRLMessage> crlMessage{signedCRLMessage};
    std::ostringstream crlStream;
    vanetza::OutputArchive archive(crlStream);
    serialize(archive, *crlMessage);
    vanetza::ByteBuffer buffer(crlStream.str().begin(), crlStream.str().end());
    payload->layer(OsiLayer::Application) = std::move(buffer);
    this->request(request, std::move(payload));
}

void RevocationAuthorityService::createSignedRACertificate()
{
    // Step 1: Create a custom certificate for the Revocation Authority
    vanetza::security::Certificate raCert;

    // Step 2: Set the signer info, nullptr since we self-sign
    raCert.signer_info = vanetza::security::SignerInfo(nullptr);

    // Step 3: Set the subject info
    raCert.subject_info.subject_type = vanetza::security::SubjectType::CRL_Signer;
    raCert.subject_info.subject_name = vanetza::ByteBuffer("Revocation Authority", "Revocation Authority" + 21);

    // Step 4: Create a SubjectAttribute for the verification key
    vanetza::security::SubjectAttribute verificationKey = vanetza::security::VerificationKey{};

    // Step 5: Convert the ecdsa256::PublicKey to PublicKey and set the verification key value
    vanetza::security::PublicKey publicKey;

    // Create an Uncompressed EccPoint from the ecdsa256::PublicKey
    vanetza::security::Uncompressed uncompressedPoint{
        vanetza::ByteBuffer(mKeyPair.public_key.x.begin(), mKeyPair.public_key.x.end()),
        vanetza::ByteBuffer(mKeyPair.public_key.y.begin(), mKeyPair.public_key.y.end())};

    // Set the public key type to ecdsa_nistp256_with_sha256
    publicKey = vanetza::security::ecdsa_nistp256_with_sha256{};
    boost::get<vanetza::security::ecdsa_nistp256_with_sha256>(publicKey).public_key = uncompressedPoint;
    boost::get<vanetza::security::VerificationKey>(verificationKey).key = publicKey;

    // Step 6: Add the verification key subject attribute to the certificate
    raCert.subject_attributes.push_back(verificationKey);

    // Step 7: Add validity restrictions to the certificate
    vanetza::security::ValidityRestriction validityRestriction;
    validityRestriction = vanetza::security::StartAndEndValidity{
        static_cast<vanetza::security::Time32>(std::time(nullptr)),                // Start validity time (current time)
        static_cast<vanetza::security::Time32>(std::time(nullptr) + 10 * 60 * 60)  // End validity time (10 hours from now)
    };
    raCert.validity_restriction.push_back(validityRestriction);

    std::cout << "Certificate Subject Type: " << static_cast<int>(raCert.subject_info.subject_type) << std::endl;
    std::cout << "Certificate Subject Name: ";
    for (const auto& byte : raCert.subject_info.subject_name) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;

    if (mBackend) {
        std::ostringstream certificateStream;
        vanetza::OutputArchive archive(certificateStream);
        serialize(archive, raCert);
        vanetza::ByteBuffer certificateBuffer(certificateStream.str().begin(), certificateStream.str().end());
        std::cout << "Certificate Buffer Size: " << certificateBuffer.size() << std::endl;

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, certificateBuffer);

        std::cout << "Signature S size: " << ecdsaSignature.s.size() << std::endl;
        std::cout << "Expected field size: " << field_size(vanetza::security::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256) << std::endl;

        if (ecdsaSignature.s.size() != field_size(vanetza::security::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256)) {
            std::cerr << "Error: Signature S size does not match expected field size!" << std::endl;
        } else {
            std::cout << "Signature S size matches expected field size." << std::endl;
        }

        if (auto uncompressed = boost::get<vanetza::security::Uncompressed>(&ecdsaSignature.R)) {
            std::cout << "Signature R X: ";
            for (const auto& byte : uncompressed->x) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            std::cout << std::endl;

            std::cout << "Signature R Y: ";
            for (const auto& byte : uncompressed->y) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
            }
            std::cout << std::endl;
        } else {
            std::cout << "Signature R is not of type Uncompressed" << std::endl;
        }

        raCert.signature = ecdsaSignature;
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    mSignedCert = raCert;

    std::cout << "Certificate signed and stored successfully." << std::endl;
}