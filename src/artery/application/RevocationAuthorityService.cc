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
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    mCrlGenInterval = 5.0;

    // Schedule the initial CRL broadcast with a delay
    auto delay = 2.0;
    scheduleAt(omnetpp::simTime() + delay, new omnetpp::cMessage("Initial CRL Broadcast"));
}

void RevocationAuthorityService::handleMessage(omnetpp::cMessage* msg)
{
    if (msg->isSelfMessage() && strcmp(msg->getName(), "Initial CRL Broadcast") == 0) {
        std::cout << "Received initial broadcast trigger:" << std::endl;
        std::cout << "  Name: " << msg->getName() << std::endl;

        std::vector<vanetza::security::Certificate> revokedCertificates;
        std::string serializedMessage = createAndSerializeCRL(revokedCertificates);
        broadcastCRLMessage(serializedMessage);

        std::cout << "CRL message sent successfully." << std::endl;
    }

    delete msg;
}

std::string RevocationAuthorityService::createAndSerializeCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates)
{
    // Step 1: Create a new CRLMessage object
    CRLMessage* crlMessage = new CRLMessage("CRL");

    // Step 2: Set the timestamp of the CRLMessage
    crlMessage->setTimestamp(omnetpp::simTime());

    // Step 3: Create a new vector to store the revoked certificate hashes
    std::vector<HashedId8> revokedCertHashes;

    // Step 4: Iterate over the revoked certificates and add their hashes to the vector
    for (const auto& cert : revokedCertificates) {
        HashedId8 hashedId = calculate_hash(cert);
        revokedCertHashes.push_back(hashedId);
    }

    // Step 5: Set the revoked certificate hashes in the CRLMessage object
    crlMessage->setRevokedCertificates(revokedCertHashes);

    // Step 6: Set the signer's certificate in the CRLMessage object
    crlMessage->setSignerCertificate(mSignedCert);

    // Step 7: Create the signature for the CRLMessage
    if (mBackend) {
        std::string serializedPayload = crlMessage->serializePayload();
        vanetza::ByteBuffer crlBuffer(serializedPayload.begin(), serializedPayload.end());
        EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, crlBuffer);
        // Step 8: Set the signature in the CRLMessage object
        crlMessage->setSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }
    // Serialize the entire CRL message
    std::string serializedMessage = crlMessage->serializeCRL();

    delete crlMessage;

    return serializedMessage;
}

void RevocationAuthorityService::broadcastCRLMessage(const std::string& serializedMessage)
{
    Enter_Method("broadcastCRLMessage");

    using namespace vanetza;
    btp::DataRequestB request;
    request.destination_port = host_cast<uint16_t>(0x00FF);
    request.gn.its_aid = aid::CRL;
    request.gn.transport_type = geonet::TransportType::SHB;
    request.gn.maximum_lifetime = geonet::Lifetime{geonet::Lifetime::Base::Ten_Seconds, 10};
    request.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
    request.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;

    // Print the serialized CRL message length
    std::cout << "Serialized CRL message length: " << serializedMessage.length() << " bytes" << std::endl;

    // Directly use the serialized CRL message as the payload
    std::unique_ptr<geonet::DownPacket> payload{new geonet::DownPacket()};
    payload->layer(OsiLayer::Application) = serializedMessage;

    // Print the payload details
    std::cout << "  Payload size: " << payload->size() << " bytes" << std::endl;

    // Send the request with the payload
    this->request(request, std::move(payload), nullptr);
}