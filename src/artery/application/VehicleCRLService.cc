#include "VehicleCRLService.h"

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "CertificateManager.h"
#include "RevocationAuthorityService.h"
#include "V2VMessageHandler.h"
#include "V2VMessage_m.h"
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

    // Create the BackendCryptoPP instance
    mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
    std::cout << "Backend created: " << (mBackend ? "Yes" : "No") << std::endl;

    // Generate the key pair and certificate once during initialization
    mKeyPair = mBackend->generate_key_pair();
    mCertificate = GenerateRoot(mKeyPair);

    mCertificateManager = std::unique_ptr<CertificateManager>(new CertificateManager());
    mCRLHandler = std::unique_ptr<CRLMessageHandler>(new CRLMessageHandler(mBackend.get(), mKeyPair, mCertificate));
    mV2VHandler = std::unique_ptr<V2VMessageHandler>(new V2VMessageHandler(mBackend.get(), mKeyPair, mCertificate));

    std::cout << "VehicleCRLService initialized." << std::endl;

    // Schedule the first trigger event
    scheduleAt(simTime() + 1.0, new cMessage("triggerEvent"));
}


void VehicleCRLService::indicate(const vanetza::btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (packet) {
        // Check if the message is a CRL message
        CRLMessage* crlMessage = dynamic_cast<CRLMessage*>(packet);
        if (crlMessage) {
            std::cout << "Received a CRLMessage. Processing..." << std::endl;
            handleCRLMessage(crlMessage);
            delete crlMessage;
            return;
        }

        // Check if the message is a V2V message
        V2VMessage* v2vMessage = dynamic_cast<V2VMessage*>(packet);
        if (v2vMessage) {
            std::cout << "Received a V2VMessage. Processing..." << std::endl;

            // Extract the certificate from the V2V message
            const vanetza::security::Certificate& cert = v2vMessage->getCertificate();

            // Check if the certificate is valid
            if (!mCertificateManager->verifyCertificate(cert)) {
                std::cout << "Invalid certificate. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

            // Check if the certificate is revoked
            vanetza::security::HashedId8 certHash = calculate_hash(cert);
            if (mCertificateManager->isRevoked(certHash)) {
                std::cout << "Certificate is revoked. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

            // Verify the signature of the V2V message
            if (!mV2VHandler->verifyV2VSignature(v2vMessage)) {
                std::cout << "Invalid signature. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

            // Process the valid and non-revoked V2V message
            processMessage(v2vMessage);
            return;
        }

        std::cout << "Received an unknown type of packet. Ignoring." << std::endl;
    } else {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
    }
}

void VehicleCRLService::discardMessage(cPacket* packet)
{
    delete packet;  // Simple way to discard the message
    std::cout << "Message discarded." << std::endl;
}

void VehicleCRLService::handleCRLMessage(CRLMessage* crlMessage)
{
    if (!mCRLHandler->verifyCRLSignature(crlMessage)) {
        std::cout << "CRL message signature verification failed." << std::endl;
        return;
    }

    std::vector<vanetza::security::HashedId8> revokedCertificates;
    for (unsigned int i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
        revokedCertificates.push_back(crlMessage->getMRevokedCertificates(i));
    }
    mCertificateManager->updateLocalCRL(revokedCertificates);

    std::cout << "CRL message processed successfully." << std::endl;
}

void VehicleCRLService::processMessage(V2VMessage* v2vMessage)
{
    // Implement V2V message processing logic
    std::cout << "Processing V2V message..., payload: " << v2vMessage->getPayload() << std::endl;
    // Process the message as needed
}

void VehicleCRLService::trigger()
{
    Enter_Method("trigger");
    using namespace vanetza;

    static const vanetza::ItsAid v2v_its_aid = 623;  // Different AID for V2V messages
    auto& mco = getFacilities().get_const<MultiChannelPolicy>();
    auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

    for (auto channel : mco.allChannels(v2v_its_aid)) {
        auto network = networks.select(channel);
        if (network) {
            btp::DataRequestB req;
            req.destination_port = host_cast(getPortNumber(channel));
            req.gn.transport_type = geonet::TransportType::SHB;
            req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
            req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
            req.gn.its_aid = v2v_its_aid;

            V2VMessage* v2vMessage = mV2VHandler->createV2VMessage();
            request(req, v2vMessage, network.get());
            std::cout << "V2V message sent." << std::endl;
        } else {
            std::cerr << "No network interface available for channel " << channel << std::endl;
        }
    }

    // Schedule the next trigger
    scheduleAt(simTime() + 1.0, new cMessage("triggerEvent"));
}

void VehicleCRLService::handleMessage(cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerEvent") == 0) {
        trigger();
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

}  // namespace artery
