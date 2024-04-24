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

using namespace artery;

void RevocationAuthorityService::initialize()
{
    // Initialize the service
    ItsG5BaseService::initialize();

    // Three different backends but this one seems very suitable, we create it here
    mBackend = vanetza::security::create_backend("backend_cryptopp");

    // Cast the Backend pointer to BackendCryptoPP and generate the key pair
    auto* cryptoPPBackend = dynamic_cast<vanetza::security::BackendCryptoPP*>(mBackend.get());
    mKeyPair = cryptoPPBackend->generate_key_pair();

    // Generate CRL, for example, every 60 seconds
    mCrlGenInterval = 60.0;
}

void RevocationAuthorityService::trigger()
{
    // This triggers the generation and broadcast of CRL, should be done periodically?
    createSignedRACertificate();
    broadcastCRLMessage();
}

CRLMessage* RevocationAuthorityService::createAndSignCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates)
{
    // Step 1: Create a new CRLMessage object
    CRLMessage* crlMessage = new CRLMessage("CRL");

    // Step 2: Set the timestamp of the CRLMessage
    //crlMessage->setTimestamp(simTime());

    // Step 3: Iterate over the revoked certificates and add their hashes to the CRLMessage
    for (const auto& cert : revokedCertificates) {
        vanetza::security::HashedId8 hashedId = vanetza::security::calculate_hash(cert);
        crlMessage->getRevokedCertificates().push_back(hashedId);
    }

    // Step 4: Sign the CRL using the RA private key
    vanetza::security::EcdsaSignature signature;
    auto* cryptoPPBackend = dynamic_cast<vanetza::security::BackendCryptoPP*>(mBackend.get());
    if (cryptoPPBackend) {
        std::ostringstream crlStream;
        vanetza::ByteBuffer crlBuffer(crlStream.str().begin(), crlStream.str().end());
        signature = cryptoPPBackend->sign_data(mKeyPair.private_key, crlBuffer);
    }

    // Step 5: Set the signature of the CRLMessage
    crlMessage->setSignature(signature);

    return crlMessage;
}

void RevocationAuthorityService::broadcastCRLMessage(CRLMessage* crlMessage)
{
    // Create a GeoNetPacket
    auto packet = new GeoNetPacket();

    // Delete the CRLMessage object
    delete crlMessage;

    // Delete the GeoNetPacket object
    delete packet;
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