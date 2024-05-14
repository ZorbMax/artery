#include "RevocationAuthorityService.h"
#include "CRLMessage.h"
#include "artery/networking/GeoNetPacket.h"
#include <vanetza/btp/data_request.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <omnetpp.h>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/data_confirm.hpp>

using namespace artery;

void RevocationAuthorityService::initialize()
{
    ItsG5BaseService::initialize();

    // Initialize the service
    mBackend = vanetza::security::create_backend("backend_cryptopp");
    auto* cryptoPPBackend = dynamic_cast<vanetza::security::BackendCryptoPP*>(mBackend.get());
    mKeyPair = cryptoPPBackend->generate_key_pair();
    mCrlGenInterval = 5.0;
    createSignedRACertificate();

    // Schedule the first CRL generation
    mTriggerMessage = new omnetpp::cMessage("CRL trigger");
    scheduleAt(omnetpp::simTime() + mCrlGenInterval, mTriggerMessage);
}

void RevocationAuthorityService::trigger()
{
    Enter_Method("trigger");

    // Generate and sign the CRL
    std::vector<vanetza::security::Certificate> revokedCertificates;
    // Add revoked certificates to the revokedCertificates vector based on your revocation criteria
    CRLMessage* signedCRLMessage = createAndSignCRL(revokedCertificates);

    // Broadcast the signed CRL message
    broadcastCRLMessage(signedCRLMessage);

    // Schedule the next CRL generation
    scheduleAt(omnetpp::simTime() + mCrlGenInterval, mTriggerMessage);
}

CRLMessage* RevocationAuthorityService::createAndSignCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates)
{
    // Step 1: Create a new CRLMessage object
    CRLMessage* crlMessage = new CRLMessage("CRL");

    // Step 2: Set the timestamp of the CRLMessage
    crlMessage->setTimestamp(omnetpp::simTime().dbl());

    // Step 3: Create a new vector to store the revoked certificate hashes
    std::vector<vanetza::security::HashedId8> revokedCertHashes;

    // Step 4: Iterate over the revoked certificates and add their hashes to the vector
    for (const auto& cert : revokedCertificates) {
        vanetza::security::HashedId8 hashedId = vanetza::security::calculate_hash(cert);
        revokedCertHashes.push_back(hashedId);
    }

    // Step 5: Set the revoked certificate hashes in the CRLMessage object
    crlMessage->setRevokedCertificates(revokedCertHashes);

    // Step 6: Set the signer's certificate in the CRLMessage objecta
    crlMessage->setSignerCertificate(mSignedCert);

    // Step 7: Create the signature for the CRLMessage
    vanetza::security::EcdsaSignature ecdsaSignature;
    auto* cryptoPPBackend = dynamic_cast<vanetza::security::BackendCryptoPP*>(mBackend.get());
    if (cryptoPPBackend) {
        std::stringstream crlStream;
        crlStream << *crlMessage;
        std::string crlString = crlStream.str();
        vanetza::ByteBuffer crlBuffer(crlString.begin(), crlString.end());
        ecdsaSignature = cryptoPPBackend->sign_data(mKeyPair.private_key, crlBuffer);
    }

    // Step 8: Set the signature in the CRLMessage object
    crlMessage->setSignature(ecdsaSignature);

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
    request.gn.maximum_lifetime = geonet::Lifetime { geonet::Lifetime::Base::One_Second, 1 };
    request.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
    request.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;

    using CrlByteBuffer = convertible::byte_buffer_impl<CRLMessage>;
    std::unique_ptr<geonet::DownPacket> payload { new geonet::DownPacket() };
    std::unique_ptr<CRLMessage> crlMessage { signedCRLMessage };
    std::unique_ptr<convertible::byte_buffer> buffer { new CrlByteBuffer(std::move(crlMessage)) };
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
    raCert.subject_info.subject_name = vanetza::ByteBuffer(std::begin("Revocation Authority"), std::end("Revocation Authority"));

    // Step 4: Create a SubjectAttribute for the verification key
    vanetza::security::SubjectAttribute verificationKey = vanetza::security::VerificationKey{};
    
    // Step 5: Convert the ecdsa256::PublicKey to PublicKey and set the verification key value
    vanetza::security::PublicKey publicKey;

    // Create an Uncompressed EccPoint from the ecdsa256::PublicKey
    vanetza::security::Uncompressed uncompressedPoint{
        vanetza::ByteBuffer(mKeyPair.public_key.x.begin(), mKeyPair.public_key.x.end()),
        vanetza::ByteBuffer(mKeyPair.public_key.y.begin(), mKeyPair.public_key.y.end())
    };

    // Set the public key type to ecdsa_nistp256_with_sha256
    publicKey = vanetza::security::ecdsa_nistp256_with_sha256{};
    boost::get<vanetza::security::ecdsa_nistp256_with_sha256>(publicKey).public_key = uncompressedPoint;
    boost::get<vanetza::security::VerificationKey>(verificationKey).key = publicKey;

    // Step 6: Add the verification key subject attribute to the certificate
    raCert.subject_attributes.push_back(verificationKey);

    // Step 7: Add validity restrictions to the certificate
    vanetza::security::ValidityRestriction validityRestriction;
    validityRestriction = vanetza::security::StartAndEndValidity{
        static_cast<vanetza::security::Time32>(std::time(nullptr)), // Start validity time (current time)
        static_cast<vanetza::security::Time32>(std::time(nullptr) + 10 * 60 * 60) // End validity time (10 hours from now)
    };
    raCert.validity_restriction.push_back(validityRestriction);

    // Step 8: Sign the certificate using the RA private key
    vanetza::security::EcdsaSignature ecdsaSignature;
    auto* cryptoPPBackend = dynamic_cast<vanetza::security::BackendCryptoPP*>(mBackend.get());
    if (cryptoPPBackend) {
        std::ostringstream certificateStream;
        vanetza::OutputArchive archive(certificateStream);
        serialize(archive, raCert);
        vanetza::ByteBuffer certificateBuffer(certificateStream.str().begin(), certificateStream.str().end());
        ecdsaSignature = cryptoPPBackend->sign_data(mKeyPair.private_key, certificateBuffer);
    }
    raCert.signature = ecdsaSignature;

    // Step 9: Store the signed certificate
    mSignedCert = raCert;
}