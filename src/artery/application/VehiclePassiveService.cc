#include "VehiclePassiveService.h"

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "EnrollmentRequest_m.h"
#include "PseudonymMessage_m.h"
#include "V2VMessageHandler.h"
#include "V2VMessage_m.h"
#include "artery/networking/GeoNetPacket.h"
#include "artery/traci/VehicleController.h"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"
#include "certify/generate-certificate.hpp"

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

Define_Module(artery::VehiclePassiveService);

using namespace artery;
using namespace vanetza::security;
using namespace omnetpp;

namespace artery
{

const vanetza::ItsAid VehiclePassiveService::ENROLLMENT_ITS_AID = 2;
const vanetza::ItsAid VehiclePassiveService::V2V_ITS_AID = 36;

void VehiclePassiveService::initialize()
{
    ItsG5Service::initialize();

    mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
    mKeyPair = mBackend->generate_key_pair();
    auto tempPseudonym = GenerateRoot(mKeyPair);

    mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));

    std::cout << "VehiclePassiveService initialized." << std::endl;
}

void VehiclePassiveService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (!packet) {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
        return;
    } 

    if (auto* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet)) {
        if (mState == VehicleState::ENROLLED) {
            delete pseudonymMessage;
            return;
        }
        handlePseudonymMessage(pseudonymMessage);
    } else if (auto* v2vMessage = dynamic_cast<V2VMessage*>(packet)) {
        handleV2VMessage(v2vMessage);
    } else {
        // std::cout << "Unknown message type. Ignoring." << std::endl;
    }

    delete packet;
}

void VehiclePassiveService::trigger()
{
    Enter_Method("trigger");

    switch (mState) {
        case VehicleState::NOT_ENROLLED:
            mKeyPair = mBackend->generate_key_pair();
            sendEnrollmentRequest();
            mRequestTime = simTime();
            mState = VehicleState::ENROLLMENT_REQUESTED;
            break;
        case VehicleState::ENROLLED:
            if(checkEnrolled()){
               sendV2VMessage(); 
            } else {
                mState = VehicleState::NOT_ENROLLED;
                std::cout << "Renewing Pseudonym" << std::endl;
            }
            break;
        case VehicleState::ENROLLMENT_REQUESTED:
            if(simTime() - mRequestTime > 0.5){
                sendEnrollmentRequest();
                mRequestTime = simTime();
            }
            break;
        default:
            break;
    }
}

bool VehiclePassiveService::checkEnrolled()
{
    simtime_t time_now = simTime();
    return convert_time32_adapted(time_now) < mPseudonymTime;
}

void VehiclePassiveService::handlePseudonymMessage(PseudonymMessage* pseudonymMessage)
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string currentVehicleId = vehicle.getVehicleId();

    if (pseudonymMessage->getPayload() != currentVehicleId) {
        return;
    }

    vanetza::security::Certificate newPseudonym = pseudonymMessage->getPseudonym();

    if (!mPseudonymHandler->verifyPseudonymSignature(pseudonymMessage)) {
        std::cout << "Invalid PseudonymMessage signature. Dropping message." << std::endl;
        return;
    }

    mPseudonymCertificate = newPseudonym;
    mV2VHandler = std::unique_ptr<V2VMessageHandler>(new V2VMessageHandler(mBackend.get(), mKeyPair, mPseudonymCertificate));
    for (const auto& restriction : mPseudonymCertificate.validity_restriction) {
        if (auto start_end = boost::get<StartAndEndValidity>(&restriction)) {
            // Accessing end_validity
            mPseudonymTime = start_end->end_validity;
        }
    }
    mState = VehicleState::ENROLLED;
    std::cout << "Pseudonym updated for vehicle " << currentVehicleId << std::endl;
}

void VehiclePassiveService::handleV2VMessage(V2VMessage* v2vMessage)
{
    if (mState != VehicleState::ENROLLED) {
        // std::cout << "Vehicle is not enrolled. Dropping message." << std::endl;
        return;
    }

    const vanetza::security::Certificate& cert = v2vMessage->getCertificate();
    vanetza::security::HashedId8 certHash = calculate_hash(cert);

    if (isRevoked(cert)) {
        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        std::string receiverId = vehicle.getVehicleId();
        std::string senderId = v2vMessage->getPayload();

        //std::cout << "=== MESSAGE DISCARDED ===" << std::endl
        //          << "Receiving vehicle: " << receiverId << std::endl
        //          << "Sender's certificate is revoked. Dropping message from vehicle " << senderId << std::endl
        //          << "=========================" << std::endl;
    }

    if (!mV2VHandler->verifyV2VSignature(v2vMessage)) {
        std::cout << "Invalid signature. Dropping message." << std::endl;
    }

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();
    // std::cout << "Vehicle " << id << " got V2V from " << v2vMessage->getPayload() << std::endl;
}

bool VehiclePassiveService::isRevoked(const vanetza::security::Certificate& certificate) const
{
    Time32 validity;
    for (const auto& restriction : certificate.validity_restriction) {
        if (auto start_end = boost::get<StartAndEndValidity>(&restriction)) {
            // Accessing end_validity
            Time32 validity = start_end->end_validity;
        }
    }
    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());
    return validity < convert_time32(time_now);
}

void VehiclePassiveService::sendEnrollmentRequest()
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();

    EnrollmentRequest* enrollmentRequest = new EnrollmentRequest();
    enrollmentRequest->setVehicleId(id.c_str());
    enrollmentRequest->setPublicKey(mKeyPair.public_key);

    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = ENROLLMENT_ITS_AID;

    request(req, enrollmentRequest);
    std::cout << "Enrollment request sent from: " << id << std::endl;
}

void VehiclePassiveService::sendV2VMessage()
{
    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();

    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = V2V_ITS_AID;

    V2VMessage* v2vMessage = mV2VHandler->createV2VMessage(id);
    v2vMessage->setCertificate(mPseudonymCertificate);
    request(req, v2vMessage);
    // std::cout << "V2V message sent." << std::endl;
}

void VehiclePassiveService::handleMessage(omnetpp::cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerEvent") == 0) {
        trigger();
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

}  // namespace artery