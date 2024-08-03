#include "VehicleHBService.h"

#include "CRLMessageHandler.h"
#include "CertificateManager.h"
#include "EnrollmentRequest_m.h"
#include "HBMessage_m.h"
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

Define_Module(artery::VehicleHBService);

using namespace artery;
using namespace vanetza::security;
using namespace omnetpp;

namespace artery
{

const vanetza::ItsAid VehicleHBService::ENROLLMENT_ITS_AID = 2;
const vanetza::ItsAid VehicleHBService::V2V_ITS_AID = 36;

void VehicleHBService::initialize()
{
    ItsG5Service::initialize();

    mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
    mKeyPair = mBackend->generate_key_pair();
    auto tempPseudonym = GenerateRoot(mKeyPair);

    mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));
    mHBHandler = std::unique_ptr<HBMessageHandler>(new HBMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));

    mState = VehicleState::NOT_ENROLLED;
    mInternalClock = simTime().dbl();

    // Custom parameters
    mTv = par("validityWindow").doubleValue();

    std::cout << "VehicleHBService initialized with Tv = " << mTv << " seconds." << std::endl;
}

void VehicleHBService::indicate(const vanetza::btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (mState == VehicleState::REVOKED) {
        delete packet;
        return;
    }

    checkDesynchronization(simTime());

    if (packet) {
        if (auto* heartbeatMessage = dynamic_cast<HBMessage*>(packet)) {
            handleHBMessage(heartbeatMessage);
        } else if (auto* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet)) {
            handlePseudonymMessage(pseudonymMessage);
        } else if (auto* v2vMessage = dynamic_cast<V2VMessage*>(packet)) {
            handleV2VMessage(v2vMessage);
        }
    }
    delete packet;
}

void VehicleHBService::trigger()
{
    Enter_Method("trigger");

    if (mState == VehicleState::REVOKED) {
        return;
    }

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();

    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;

    if (mState == VehicleState::NOT_ENROLLED) {
        req.gn.its_aid = ENROLLMENT_ITS_AID;

        EnrollmentRequest* enrollmentRequest = new EnrollmentRequest();
        enrollmentRequest->setVehicleId(id.c_str());
        enrollmentRequest->setPublicKey(mKeyPair.public_key);

        request(req, enrollmentRequest);
        std::cout << "Enrollment request sent from: " << id << std::endl;

        mState = VehicleState::ENROLLMENT_REQUESTED;
    } else if (mState == VehicleState::ENROLLED) {
        req.gn.its_aid = V2V_ITS_AID;

        V2VMessage* v2vMessage = mV2VHandler->createV2VMessage(id);
        v2vMessage->setCertificate(mPseudonymCertificate);
        request(req, v2vMessage);
    }
}

void VehicleHBService::handlePseudonymMessage(PseudonymMessage* pseudonymMessage)
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
    mState = VehicleState::ENROLLED;
    std::cout << "Pseudonym updated for vehicle " << currentVehicleId << std::endl;
}

void VehicleHBService::handleHBMessage(HBMessage* heartbeatMessage)
{
    if (mState != VehicleState::ENROLLED) {
        return;
    }

    if (!mHBHandler->verifyHeartbeatSignature(heartbeatMessage)) {
        std::cout << "Heartbeat message signature verification failed." << std::endl;
        return;
    }

    double heartbeatTimestamp = heartbeatMessage->getMTimestamp().dbl();

    if (heartbeatTimestamp >= mInternalClock - mTv) {
        mInternalClock = std::max(mInternalClock, heartbeatTimestamp);

        vanetza::security::HashedId8 ownHash = vanetza::security::calculate_hash(mPseudonymCertificate);

        for (unsigned int i = 0; i < heartbeatMessage->getPRLArraySize(); ++i) {
            const vanetza::security::HashedId8& revokedId = heartbeatMessage->getPRL(i);
            if (revokedId == ownHash) {
                performSelfRevocation();
                // Logger::log("SELF_REVOKE," + std::to_string(simTime().dbl()) + "," + hashedId8ToHexString(ownHash));
                return;
            }
        }
    } else {
        std::cout << "Received outdated heartbeat message. Dropping." << std::endl;
    }
}

void VehicleHBService::handleV2VMessage(V2VMessage* v2vMessage)
{
    if (mState != VehicleState::ENROLLED) {
        // std::cout << "Vehicle is not enrolled. Dropping message." << std::endl;
        return;
    }

    simtime_t messageTimestamp = v2vMessage->getTimestamp();
    if (messageTimestamp < mInternalClock - mTv) {
        std::cout << "Received outdated V2V message. Dropping." << std::endl;
        return;
    }

    if (!mV2VHandler || !mV2VHandler->verifyV2VSignature(v2vMessage)) {
        std::cout << "Invalid signature. Dropping message." << std::endl;
        return;
    }

    vanetza::security::Certificate pseudo = v2vMessage->getCertificate();
    vanetza::security::HashedId8 hashedId = calculate_hash(pseudo);
    Logger::log("RECV," + std::to_string(simTime().dbl()) + "," + hashedId8ToHexString(hashedId));
}

void VehicleHBService::checkDesynchronization(simtime_t messageTimestamp)
{
    if (messageTimestamp.dbl() > mInternalClock + mTv) {
        performSelfRevocation();
    }
}

void VehicleHBService::performSelfRevocation()
{
    if (mState != VehicleState::REVOKED) {
        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        std::cout << "Vehicle " << vehicle.getVehicleId() << " has been self-revoked." << std::endl;

        mPseudonymCertificate = vanetza::security::Certificate();
        mV2VHandler.reset();
        mState = VehicleState::REVOKED;
    }
}

// Helper function to convert HashedId8 to hex string
std::string VehicleHBService::hashedId8ToHexString(const vanetza::security::HashedId8& hashedId)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : hashedId) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

}  // namespace artery
