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
    mTimer = &getFacilities().get_const<Timer>();
    mBackend = vanetza::security::create_backend("backend_cryptopp"); // Three different backends but this one seems very suitable, we create it here
    mKeyPair = mBackend->generate_key_pair(); // Generate a key pair for the RA using the cryptopp backend
    mCrlGenInterval = 60.0; // Generate CRL every 60 seconds
    mNextCrlGenTime = mTimer->getCurrentTime() + mCrlGenInterval; 
}

void RevocationAuthorityService::trigger()
{
    auto now = mTimer->getCurrentTime();
    if (now >= mNextCrlGenTime) { // Check if current time has reached next CRL gen time
        generateCrl();
        signCrl();
        broadcastCrl();
        mNextCrlGenTime = now + mCrlGenInterval; // Update next CRL gen time
    }
}

void RevocationAuthorityService::indicate(const vanetza::btp::DataIndication&, std::unique_ptr<vanetza::UpPacket> packet)
{
    // Process received packets if needed
    // For example, handle certificate revocation requests from authorities
    // and add the requested certificates to the revocation list
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


void RevocationAuthorityService::broadcastCrl()
{
    // Create a GeoNetPacket containing the signed CRL
    auto packet = std::make_unique<GeoNetPacket>(vanetza::geonet::GeoNetProtocolVersion::latest);
    packet->insertPayload(mSignedCrl);

    // Set the destination to broadcast
    packet->setDestination(vanetza::geonet::Area { vanetza::geonet::Continent::EUROPE });

    // Set the communication profile
    packet->setCommProfile(vanetza::geonet::CommProfile::ITS_G5);

    // Set the maximum hop limit
    packet->setMaxHopLimit(5);

    // Create a BTP data request
    vanetza::btp::DataRequestB request;
    request.destination_port = host_cast<uint16_t>(mChannel);
    request.gn.its_aid = aid::CA;
    request.gn.transport_type = vanetza::geonet::TransportType::GBC;
    request.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP2));
    request.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;

    // Broadcast the CRL
    using namespace vanetza;
    btp::DataRequestB dataRequest(request);
    dataRequest.data = std::move(packet);
    request(dataRequest, std::move(dataRequest.data));
}