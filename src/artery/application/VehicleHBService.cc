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

void VehicleHBService::initialize()
{
    ItsG5Service::initialize();

    mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
    std::cout << "Backend created: " << (mBackend ? "Yes" : "No") << std::endl;

    mKeyPair = mBackend->generate_key_pair();
    auto tempPseudonym = GenerateRoot(mKeyPair);

    mCertificateManager = std::unique_ptr<CertificateManager>(new CertificateManager());
    mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));
    mHBHandler = std::unique_ptr<HBMessageHandler>(new HBMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));

    enrollmentRequestSent = false;
    enrolled = false;
    mIsRevoked = false;
    mInternalClock = simTime().dbl();
    mTv = 20.0;  // validity window
    mLastActionTime = simTime();
    mActionInterval = 2;

    scheduleAt(simTime() + 1, new cMessage("triggerEvent"));
    std::cout << "VehicleHBService initialized." << std::endl;
}


void VehicleHBService::indicate(const vanetza::btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (mIsRevoked) {
        // std::cout << "Vehicle is revoked. Dropping all incoming messages." << std::endl;
        delete packet;
        return;
    }

    // if the vehicle is trying to evade HB messages this makes sure we will still revoke eventually.
    checkAutomaticRevocation(simTime());

    if (packet) {
        HBMessage* heartbeatMessage = dynamic_cast<HBMessage*>(packet);
        if (heartbeatMessage) {
            handleHBMessage(heartbeatMessage);
            delete heartbeatMessage;
            return;
        }

        PseudonymMessage* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet);
        if (pseudonymMessage) {
            handlePseudonymMessage(pseudonymMessage);
            delete pseudonymMessage;
            return;
        }

        V2VMessage* v2vMessage = dynamic_cast<V2VMessage*>(packet);
        if (v2vMessage) {
            handleV2VMessage(v2vMessage);
            return;
        }
    }
    delete packet;
}

void VehicleHBService::discardMessage(cPacket* packet)
{
    delete packet;
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

    // TODO: Step 4: Verify the CA's Certificate

    // Step 5: Update pseudonym certificate
    mPseudonymCertificate = newPseudonym;
    mV2VHandler = std::unique_ptr<V2VMessageHandler>(new V2VMessageHandler(mBackend.get(), mKeyPair, mPseudonymCertificate));
    enrolled = true;
    std::cout << "Pseudonym updated for vehicle " << currentVehicleId << std::endl;
}

// Helper function to convert HashedId8 to hex string
std::string hashedId8ToHexString(const vanetza::security::HashedId8& hashedId)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : hashedId) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

void VehicleHBService::handleHBMessage(HBMessage* heartbeatMessage)
{
    if (!enrolled) {
        return;
    }

    if (!mHBHandler->verifyHeartbeatSignature(heartbeatMessage)) {
        std::cout << "Heartbeat message signature verification failed." << std::endl;
        return;
    }

    double heartbeatTimestamp = heartbeatMessage->getMTimestamp().dbl();

    if (heartbeatTimestamp >= mInternalClock - mTv) {
        double oldClock = mInternalClock;
        mInternalClock = std::max(mInternalClock, heartbeatTimestamp);

        std::cout << "Internal clock updated from " << oldClock << " to " << mInternalClock << std::endl;

        const auto prlSize = heartbeatMessage->getPRLArraySize();
        // std::cout << "PRL size: " << prlSize << std::endl;

        vanetza::security::HashedId8 ownHash = vanetza::security::calculate_hash(mPseudonymCertificate);
        //::cout << "Own certificate hash: " << hashedId8ToHexString(ownHash) << std::endl;

        for (unsigned int i = 0; i < prlSize; ++i) {
            const vanetza::security::HashedId8& revokedId = heartbeatMessage->getPRL(i);
            // std::cout << "Checking revoked ID at index " << i << ": " << hashedId8ToHexString(revokedId) << std::endl;

            if (revokedId == ownHash) {
                // std::cout << "Match found! Performing self-revocation." << std::endl;
                performSelfRevocation();
                return;
            }
        }
        std::cout << "No matching revoked ID found in PRL." << std::endl;
    } else {
        std::cout << "Received outdated heartbeat message. Ignoring." << std::endl;
    }
}

void VehicleHBService::handleV2VMessage(V2VMessage* v2vMessage)
{
    if (!enrolled) {
        // std::cout << "Vehicle is not enrolled. Dropping message." << std::endl;
        delete v2vMessage;
        return;
    }

    simtime_t messageTimestamp = v2vMessage->getTimestamp();
    if (messageTimestamp < mInternalClock - mTv) {
        std::cout << "Received outdated V2V message. Dropping." << std::endl;
        delete v2vMessage;
        return;
    }

    const vanetza::security::Certificate& cert = v2vMessage->getCertificate();
    if (!mCertificateManager->verifyCertificate(cert)) {
        std::cout << "Invalid certificate. Dropping message." << std::endl;
        delete v2vMessage;
        return;
    }

    if (!mV2VHandler->verifyV2VSignature(v2vMessage)) {
        std::cout << "Invalid signature. Dropping message." << std::endl;
        delete v2vMessage;
        return;
    }

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();
    std::cout << "Vehicle " + id + " got V2V from " << v2vMessage->getPayload() << std::endl;

    delete v2vMessage;
}

void VehicleHBService::checkAutomaticRevocation(simtime_t messageTimestamp)
{
    if (messageTimestamp.dbl() > mInternalClock + mTv) {
        performSelfRevocation();
    }
}

void VehicleHBService::performSelfRevocation()
{
    if (!mIsRevoked) {
        mIsRevoked = true;
        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        std::cout << "Vehicle " << vehicle.getVehicleId() << " has been self-revoked." << std::endl;

        // Clear credentials
        mPseudonymCertificate = vanetza::security::Certificate();
        mV2VHandler.reset();
    }
}

void VehicleHBService::trigger()
{
    Enter_Method("trigger");
    using namespace vanetza;

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();

    if (mIsRevoked) {
        // std::cout << "Vehicle " + id + " is revoked. Not sending any messages." << std::endl;
        return;
    }

    if (simTime() - mLastActionTime >= mActionInterval) {
        if (!enrollmentRequestSent) {
            EnrollmentRequest* enrollmentRequest = new EnrollmentRequest();
            enrollmentRequest->setVehicleId(id.c_str());
            enrollmentRequest->setPublicKey(mKeyPair.public_key);

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
        mLastActionTime = simTime();
    }
}

void VehicleHBService::handleMessage(cMessage* msg)
{
    if (msg && strcmp(msg->getName(), "triggerEvent") == 0) {
        trigger();
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}
}  // namespace artery
