#include "RevocationAuthorityService.h"

#include "CRLMessage.h"
#include "artery/networking/GeoNetPacket.h"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <arpa/inet.h>
#include <omnetpp.h>
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

using namespace artery;
using namespace vanetza::security;
using namespace omnetpp;

Define_Module(RevocationAuthorityService)

void RevocationAuthorityService::initialize()
{
    ItsG5Service::initialize();

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
    // auto delay = 2.0;
    // scheduleAt(omnetpp::simTime() + delay, new omnetpp::cMessage("Initial CRL Broadcast"));
}

void RevocationAuthorityService::trigger()
{
    Enter_Method("trigger");
    using namespace vanetza;

    static const vanetza::ItsAid crl_its_aid = 622;
    auto& mco = getFacilities().get_const<MultiChannelPolicy>();
    auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

    for (auto channel : mco.allChannels(crl_its_aid)) {
        auto network = networks.select(channel);
        if (network) {
            btp::DataRequestB req;
            req.destination_port = host_cast(getPortNumber(channel));
            req.gn.transport_type = geonet::TransportType::SHB;
            req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
            req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
            req.gn.its_aid = crl_its_aid;

            std::vector<vanetza::security::Certificate> revokedCertificates;
            std::string serializedMessage = createAndSerializeCRL(revokedCertificates);

            // Create a cPacket and set the payload
            cPacket* packet = new cPacket("CRLMessage");
            packet->setByteLength(serializedMessage.size());                                        
            packet->encapsulate(new cPacket(serializedMessage.c_str(), serializedMessage.size()));

            std::cout << "Sending CRL message on channel " << channel << " to port " << req.destination_port << std::endl;

            request(req, packet, network.get());
            std::cout << "CRL message sent." << std::endl;
        } else {
            std::cerr << "No network interface available for channel " << channel << std::endl;
        }
    }
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

// void RevocationAuthorityService::broadcastCRLMessage(const std::string& serializedMessage)
// {
//     using namespace vanetza;
//     static const vanetza::ItsAid crl_its_aid = 622;

//     auto& facilities = getFacilities();
//     auto& mco = facilities.get_const<MultiChannelPolicy>();
//     auto& networks = facilities.get_const<NetworkInterfaceTable>();

//     for (auto channel : mco.allChannels(crl_its_aid)) {
//         auto network = networks.select(channel);
//         if (network) {
//             btp::DataRequestB req;
//             req.destination_port = host_cast<uint16_t>(0xFFFF);
//             req.gn.transport_type = geonet::TransportType::SHB;
//             req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
//             req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
//             req.gn.its_aid = crl_its_aid;

//             std::cout << "Broadcasting CRL message on channel: " << channel << " with length: " << serializedMessage.length() << " bytes" << std::endl;

//             // Create a geonet::DownPacket with the serialized CRL message as payload
//             std::unique_ptr<geonet::DownPacket> payload{new geonet::DownPacket()};
//             payload->layer(OsiLayer::Application) = serializedMessage;

//             // Print the payload details for debugging
//             std::cout << "Payload size: " << payload->size() << " bytes" << std::endl;

//             // Send the request with the payload
//             this->request(req, std::move(payload), network.get());
//             std::cout << "Broadcast request sent on channel " << channel << "." << std::endl;
//         } else {
//             std::cerr << "No network interface available for channel " << channel << std::endl;
//         }
//     }
// }

// void RevocationAuthorityService::handleMessage(omnetpp::cMessage* msg)
// {
//     if (msg->isSelfMessage() && strcmp(msg->getName(), "Initial CRL Broadcast") == 0) {
//         std::cout << "Received initial broadcast trigger:" << std::endl;
//         std::cout << "  Name: " << msg->getName() << std::endl;

//         std::vector<vanetza::security::Certificate> revokedCertificates;
//         std::string serializedMessage = createAndSerializeCRL(revokedCertificates);
//         broadcastCRLMessage(serializedMessage);

//         std::cout << "CRL message sent successfully." << std::endl;
//     }

//     delete msg;
// }