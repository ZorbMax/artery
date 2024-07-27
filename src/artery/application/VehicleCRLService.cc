#include "VehicleCRLService.h"

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
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

const vanetza::ItsAid VehicleCRLService::ENROLLMENT_ITS_AID = 2;
const vanetza::ItsAid VehicleCRLService::V2V_ITS_AID = 36;

void VehicleCRLService::initialize()
{
    ItsG5Service::initialize();

    mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
    mKeyPair = mBackend->generate_key_pair();
    auto tempPseudonym = GenerateRoot(mKeyPair);

    mCRLHandler = std::unique_ptr<CRLMessageHandler>(new CRLMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));
    mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, tempPseudonym));

    std::cout << "VehicleCRLService initialized." << std::endl;
}

void VehicleCRLService::indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (!packet) {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
        return;
    }

    if (auto* crlMessage = dynamic_cast<CRLMessage*>(packet)) {
        handleCRLMessage(crlMessage);
    } else if (auto* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet)) {
        if (mState == VehicleState::ENROLLED) {
            return;
        }
        handlePseudonymMessage(pseudonymMessage);
    } else if (auto* v2vMessage = dynamic_cast<V2VMessage*>(packet)) {
        handleV2VMessage(v2vMessage);
    } else {
        std::cout << "Unknown message type. Ignoring." << std::endl;
    }

    delete packet;
}

void VehicleCRLService::trigger()
{
    Enter_Method("trigger");

    switch (mState) {
        case VehicleState::NOT_ENROLLED:
            sendEnrollmentRequest();
            mState = VehicleState::ENROLLMENT_REQUESTED;
            break;
        case VehicleState::ENROLLED:
            sendV2VMessage();
            break;
        default:
            // Do nothing while waiting for enrollment response
            break;
    }
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
    updateLocalCRL(revokedCertificates);
}

void VehicleCRLService::handlePseudonymMessage(PseudonymMessage* pseudonymMessage)
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

void VehicleCRLService::handleV2VMessage(V2VMessage* v2vMessage)
{
    if (mState != VehicleState::ENROLLED) {
        std::cout << "Vehicle is not enrolled. Dropping message." << std::endl;
        return;
    }

    const vanetza::security::Certificate& cert = v2vMessage->getCertificate();
    vanetza::security::HashedId8 certHash = calculate_hash(cert);

    if (isRevoked(certHash)) {
        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        std::string receiverId = vehicle.getVehicleId();
        std::string senderId = v2vMessage->getPayload();

        std::cout << "=== MESSAGE DISCARDED ===" << std::endl
                  << "Receiving vehicle: " << receiverId << std::endl
                  << "Sender's certificate is revoked. Dropping message from vehicle " << senderId << std::endl
                  << "=========================" << std::endl;
    }

    if (!mV2VHandler->verifyV2VSignature(v2vMessage)) {
        std::cout << "Invalid signature. Dropping message." << std::endl;
    }

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    std::string id = vehicle.getVehicleId();
    std::cout << "Vehicle " << id << " got V2V from " << v2vMessage->getPayload() << std::endl;
}

void VehicleCRLService::updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates)
{
    mLocalCRL.insert(mLocalCRL.end(), revokedCertificates.begin(), revokedCertificates.end());
    std::sort(mLocalCRL.begin(), mLocalCRL.end());
    mLocalCRL.erase(std::unique(mLocalCRL.begin(), mLocalCRL.end()), mLocalCRL.end());
}

bool VehicleCRLService::isRevoked(const vanetza::security::HashedId8& certificateHash) const
{
    return std::binary_search(mLocalCRL.begin(), mLocalCRL.end(), certificateHash);
}

void VehicleCRLService::sendEnrollmentRequest()
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

void VehicleCRLService::sendV2VMessage()
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
    std::cout << "V2V message sent." << std::endl;
}

void VehicleCRLService::handleMessage(omnetpp::cMessage* msg)
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

}  // namespace artery