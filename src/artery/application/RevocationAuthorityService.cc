#include "RevocationAuthorityService.h"
#include "artery/networking/GeoNetPacket.h"
#include <vanetza/btp/data_request.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>

using namespace artery;

void RevocationAuthorityService::initialize()
{
    // Initialize the service
    ItsG5BaseService::initialize();
    mBackend = vanetza::security::create_backend("backend_cryptopp"); // Three different backends but this one seems very suitable, we create it here
    mKeyPair = mBackend->generate_key_pair(); // Generate a key pair for the RA using the cryptopp backend
    mCrlGenInterval = 60.0; // Generate CRL, for example, every 60 seconds
}

void RevocationAuthorityService::trigger()
{
    // This triggers the generation and broadcast of CRL, should be done periodically?
    generateCrl();
    signCrl();
    broadcastCrl();
}

void RevocationAuthorityService::generateCrl()
{
    // Generate the Certificate Revocation List (CRL)
    mCrl.clear();

    // Add revoked certificate IDs to mCrl
    for (const auto& certId : mRevokedCertIds) {
        mCrl.insert(certId);
    }
}

void RevocationAuthorityService::signCrl() {
    // Create a custom certificate for the Revocation Authority
    vanetza::security::Certificate raCert;

    // Set the signer info
    raCert.signer_info = vanetza::security::SignerInfo(nullptr);
    raCert.signer_info.subject_type = vanetza::security::SubjectType::CRL_Signer;

    // Set the subject info
    raCert.subject_info.subject_type = vanetza::security::SubjectType::CRL_Signer;
    raCert.subject_info.subject_name = ByteBuffer("Revocation Authority");

    // Add the verification key as a subject attribute
    vanetza::security::SubjectAttribute verificationKey;
    verificationKey.type = vanetza::security::SubjectAttributeType::Verification_Key;
    verificationKey.value = vanetza::security::VerificationKey{ mKeyPair.public_key };
    raCert.subject_attributes.push_back(verificationKey);

    // Add validity restrictions
    vanetza::security::ValidityRestriction validityRestriction;
    validityRestriction = vanetza::security::StartAndEndValidity{
        static_cast<Time32>(std::time(nullptr)), // Start validity time (current time)
        static_cast<Time32>(std::time(nullptr) + 10 * 60 * 60) // End validity time (10 hours from now)
    };
    raCert.validity_restriction.push_back(validityRestriction);

    // Sign the CRL using the Revocation Authority's private key
    vanetza::security::EcdsaSignature crlSignature;
    mBackend->sign_data(mKeyPair.private_key, mCrl, crlSignature);
    raCert.signature = crlSignature;

    mSignedCrl = raCert;
}

void RevocationAuthority::broadcastCRL()
{
    // Create a ShbDataRequest with default parameters
    vanetza::geonet::ShbDataRequest shbRequest;

    // Set the necessary parameters (vanetza/geonet/data_request.hpp)
    shbRequest.upper_protocol = vanetza::geonet::UpperProtocol::BTP_B;
    shbRequest.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    shbRequest.its_aid = vanetza::aid::CRL;
    shbRequest.maximum_lifetime = vanetza::geonet::Lifetime(vanetza::units::seconds(60));
    shbRequest.max_hop_limit = 10;
    shbRequest.traffic_class = vanetza::geonet::TrafficClass::TC_ST;

    // Serialize the CRL into a byte buffer
    std::vector<uint8_t> serializedCRL = serializeCRL();

    // Create a DataRequestVariant and set it to the ShbDataRequest
    vanetza::geonet::DataRequestVariant request = std::move(shbRequest);

    // Access the payload of the DataRequestVariant and set the serialized CRL
    vanetza::access_request(request).payload = std::move(serializedCRL);

    // Create a GeoNetworking router
    vanetza::geonet::Router gnRouter;

    // Broadcast the CRL using GN
    gnRouter.request(request);
}

std::vector<uint8_t> RevocationAuthorityService::serializeCRL() const
{
    // Create a byte buffer to store the serialized CRL
    std::vector<uint8_t> serializedCRL;

    // Serialize the signed CRL certificate
    // How, where?
    // Serialize the revoked certificate IDs

    return serializedCRL;
}