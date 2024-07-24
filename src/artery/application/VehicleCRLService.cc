#include "VehicleCRLService.h"

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "CertificateManager.h"
#include "EnrollmentRequest_m.h"
#include "PseudonymMessage_m.h"
#include "RevocationAuthorityService.h"
#include "V2VMessageHandler.h"
#include "V2VMessage_m.h"
#include "artery/networking/GeoNetPacket.h"
#include "artery/traci/VehicleController.h"
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
    auto tempPseudonym = GenerateRoot(mKeyPair);

    mCertificateManager = std::unique_ptr<CertificateManager>(new CertificateManager());
    mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));
    mCRLHandler = std::unique_ptr<CRLMessageHandler>(new CRLMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));

    std::cout << "VehicleCRLService initialized." << std::endl;

    // Initialize the flag to false
    enrollmentRequestSent = false;
    enrolled = false;

    // Schedule the first trigger event
    scheduleAt(simTime() + 200.0, new cMessage("triggerEvent"));
}


void VehicleCRLService::indicate(const vanetza::btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (packet) {
        // Check if the message is a CRL message
        CRLMessage* crlMessage = dynamic_cast<CRLMessage*>(packet);
        if (crlMessage) {
            // std::cout << "Received a CRLMessage. Processing..." << std::endl;
            handleCRLMessage(crlMessage);
            delete crlMessage;
            return;
        }

        // Check if the message is a Pseudonym Message (Enrollment Response)
        PseudonymMessage* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet);
        if (pseudonymMessage) {
            auto& vehicle = getFacilities().get_const<traci::VehicleController>();
            std::string id = vehicle.getVehicleId();
            std::cout << "Vehicle " + id + " got PS for " + pseudonymMessage->getPayload() << std::endl;
            handlePseudonymMessage(pseudonymMessage);
            delete pseudonymMessage;
            return;
        }

        // Check if the message is a V2V message
        V2VMessage* v2vMessage = dynamic_cast<V2VMessage*>(packet);
        if (v2vMessage) {
            std::cout << "Received a V2VMessage. Processing..." << std::endl;

            if (!enrolled) {
                std::cout << "Vehicle is not enrolled. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

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
                auto& vehicle = getFacilities().get_const<traci::VehicleController>();
                std::string receiverId = vehicle.getVehicleId();
                std::string senderId = v2vMessage->getPayload();

                std::cout << "=== MESSAGE DISCARDED ===" << std::endl;
                std::cout << "Receiving vehicle: " << receiverId << std::endl;
                std::cout << "Sender's certificate is revoked. Dropping message from vehicle " << senderId << std::endl;
                std::cout << "=========================" << std::endl;

                Logger::log("MESSAGE_DISCARDED," + std::to_string(simTime().dbl()) + "," + convertToHexString(certHash));

                discardMessage(v2vMessage);
                return;
            }

            // Verify the signature of the V2V message
            if (!mV2VHandler->verifyV2VSignature(v2vMessage)) {
                std::cout << "Invalid signature. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

            handleV2VMessage(v2vMessage);
            return;
        }
    } else {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
    }
    delete packet;
}

void VehicleCRLService::discardMessage(cPacket* packet)
{
    delete packet;
    // std::cout << "Message discarded." << std::endl;
}

void VehicleCRLService::handlePseudonymMessage(PseudonymMessage* pseudonymMessage)
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string currentVehicleId = vehicle.getVehicleId();

    // Step 1: Check if the message is intended for this vehicle
    if (pseudonymMessage->getPayload() != currentVehicleId) {
        // std::cout << "PseudonymMessage is not intended for this vehicle. Ignoring message." << std::endl;
        return;
    }

    // Step 2: Extract pseudonym cert
    vanetza::security::Certificate newPseudonym = pseudonymMessage->getPseudonym();

    // Step 3: Verify the signature
    if (!mPseudonymHandler->verifyPseudonymSignature(pseudonymMessage)) {
        std::cout << "Invalid PseudonymMessage signature. Dropping message." << std::endl;
        return;
    }

    // TODO: Step 4: Verify the CA's Certificate

    // Step 5: Update pseudonym certificate
    mPseudonymCertificate = newPseudonym;
    mV2VHandler = std::unique_ptr<V2VMessageHandler>(new V2VMessageHandler(mBackend.get(), mKeyPair, mPseudonymCertificate));
    enrolled = true;
    std::cout << "Pseudonym updated for vehicle " << currentVehicleId << std::endl;
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

    // std::cout << "CRL message processed successfully." << std::endl;
}

void VehicleCRLService::handleV2VMessage(V2VMessage* v2vMessage)
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();
    // Implement V2V message processing logic
    std::cout << "Vehicle " + id + " got V2V from " << v2vMessage->getPayload() << std::endl;
    // Process the message as needed
    delete v2vMessage;
}

void VehicleCRLService::trigger()
{
    Enter_Method("trigger");
    using namespace vanetza;

    if (!enrollmentRequestSent) {
        // Send enrollment request
        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        std::string id = vehicle.getVehicleId();

        EnrollmentRequest* enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest->setVehicleId(id.c_str());
        enrollmentRequest->setPublicKey(mKeyPair.public_key);

        // Send the enrollment request to the CA
        static const vanetza::ItsAid enrollment_its_aid = 622;
        auto& mco = getFacilities().get_const<MultiChannelPolicy>();
        auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

        for (auto channel : mco.allChannels(enrollment_its_aid)) {
            auto network = networks.select(channel);
            if (network) {
                btp::DataRequestB req;
                req.destination_port = host_cast(getPortNumber(channel));
                req.gn.transport_type = geonet::TransportType::SHB;
                req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
                req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
                req.gn.its_aid = enrollment_its_aid;

                request(req, enrollmentRequest, network.get());
                std::cout << "Enrollment request sent from: " + id << std::endl;
            } else {
                std::cerr << "No network interface available for channel " << channel << std::endl;
            }
        }

        enrollmentRequestSent = true;
    } else {
        static const vanetza::ItsAid v2v_its_aid = 623;
        auto& mco = getFacilities().get_const<MultiChannelPolicy>();
        auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        std::string id = vehicle.getVehicleId();

        for (auto channel : mco.allChannels(v2v_its_aid)) {
            auto network = networks.select(channel);
            if (network) {
                btp::DataRequestB req;
                req.destination_port = host_cast(getPortNumber(channel));
                req.gn.transport_type = geonet::TransportType::SHB;
                req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
                req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
                req.gn.its_aid = v2v_its_aid;

                V2VMessage* v2vMessage = mV2VHandler->createV2VMessage(id);
                v2vMessage->setCertificate(mPseudonymCertificate);
                request(req, v2vMessage, network.get());
                std::cout << "V2V message sent." << std::endl;
            } else {
                std::cerr << "No network interface available for channel " << channel << std::endl;
            }
        }
    }

    // Schedule the next trigger
    scheduleAt(simTime() + 200.0, new cMessage("triggerEvent"));
}
}  // namespace artery

void VehicleCRLService::handleMessage(cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerEvent") == 0) {
        trigger();
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

std::string VehicleCRLService::convertToHexString(const vanetza::security::HashedId8& hashedId)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : hashedId) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// namespace artery