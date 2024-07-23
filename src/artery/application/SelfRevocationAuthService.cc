#include "SelfRevocationAuthService.h"

#include "HBMessage_m.h"
#include "PseudonymMessage_m.h"
#include "artery/networking/GeoNetPacket.h"
#include "certify/generate-certificate.hpp"
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

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

Define_Module(artery::SelfRevocationAuthService)

using namespace artery;
using namespace vanetza;
using namespace security;
using namespace omnetpp;

void SelfRevocationAuthService::initialize()
{
    CentralAuthService::initialize();

    mHeartbeatInterval = 1.5;
    mRevocationInterval = 5.0;
    mTv = 20.0; //validity window
    mTeff = 2 * mTv;

    scheduleAt(simTime() + mHeartbeatInterval, new cMessage("triggerHeartbeat"));
    scheduleAt(simTime() + mRevocationInterval, new cMessage("triggerRevocation"));
}

void SelfRevocationAuthService::handleMessage(cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerHeartbeat") == 0) {
        removeExpiredRevocations();
        generateAndSendHeartbeat();
        scheduleAt(simTime() + mHeartbeatInterval, msg);
    } else if (strcmp(msg->getName(), "triggerRevocation") == 0) {
        revokeRandomCertificate();
        scheduleAt(simTime() + mRevocationInterval, msg);
    } else if (dynamic_cast<EnrollmentRequest*>(msg)) {
        handleEnrollmentRequest(static_cast<EnrollmentRequest*>(msg));
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

void SelfRevocationAuthService::generateAndSendHeartbeat()
{
    using namespace vanetza;

    static const vanetza::ItsAid heartbeat_its_aid = 622;
    auto& mco = getFacilities().get_const<MultiChannelPolicy>();
    auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

    for (auto channel : mco.allChannels(heartbeat_its_aid)) {
        auto network = networks.select(channel);
        if (network) {
            btp::DataRequestB req;
            req.destination_port = host_cast(getPortNumber(channel));
            req.gn.transport_type = geonet::TransportType::SHB;
            req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
            req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
            req.gn.its_aid = heartbeat_its_aid;

            HBMessage* hbMessage = createAndPopulateHeartbeat();
            request(req, hbMessage, network.get());
            std::cout << "Heartbeat message sent. Revoked certificates: " << mMasterPRL.size() << std::endl;
        } else {
            std::cerr << "No network interface available for channel " << channel << std::endl;
        }
    }
}

HBMessage* SelfRevocationAuthService::createAndPopulateHeartbeat()
{
    HBMessage* hbMessage = new HBMessage("Heartbeat");

    hbMessage->setMTimestamp(omnetpp::simTime());

    // std::cout << "Creating heartbeat message at time: " << omnetpp::simTime().dbl() << std::endl;
    // std::cout << "Number of entries in mMasterPRL: " << mMasterPRL.size() << std::endl;

    hbMessage->setPRLArraySize(mMasterPRL.size());

    size_t index = 0;
    for (const auto& entry : mMasterPRL) {
        // std::cout << "Adding PRL entry at index " << index << std::endl;
        hbMessage->setPRL(index, entry.first);
        index++;
    }

    hbMessage->setMSignerCertificate(mRootCert);

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(hbMessage->getMTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

        for (size_t i = 0; i < hbMessage->getPRLArraySize(); ++i) {
            auto& hash = hbMessage->getPRL(i);
            dataToSign.insert(dataToSign.end(), hash.data(), hash.data() + hash.size());
        }

        vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(hbMessage->getMSignerCertificate());
        dataToSign.insert(dataToSign.end(), serializedCert.begin(), serializedCert.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        hbMessage->setMSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return hbMessage;
}

void SelfRevocationAuthService::revokeRandomCertificate()
{
    if (mIssuedCertificates.empty()) {
        return;
    }

    // Select a random certificate
    auto it = mIssuedCertificates.begin();
    std::advance(it, rand() % mIssuedCertificates.size());

    // Calculate the hash of the certificate
    vanetza::security::HashedId8 hashedId = calculate_hash(it->second);

    // Add the hash to the master PRL if it's not already there
    if (mMasterPRL.find(hashedId) == mMasterPRL.end()) {
        mMasterPRL[hashedId] = simTime().dbl();
    }

    std::string vehicleId = it->first;

    mIssuedCertificates.erase(it);

    std::cout << "=== REVOCATION EVENT ===" << std::endl;
    std::cout << "Vehicle " << vehicleId << " has been revoked." << std::endl;
    std::cout << "Master PRL size: " << mMasterPRL.size() << std::endl;
    std::cout << "========================" << std::endl;
}

std::string SelfRevocationAuthService::convertToHexString(const vanetza::security::HashedId8& hashedId)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : hashedId) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

void SelfRevocationAuthService::removeExpiredRevocations()
{
    auto currentTime = simTime().dbl();
    auto it = mMasterPRL.begin();
    int removedCount = 0;

    std::cout << "\n=== REMOVING EXPIRED REVOCATIONS ===" << std::endl;
    std::cout << "Current time: " << currentTime << std::endl;

    while (it != mMasterPRL.end()) {
        double entryAge = currentTime - it->second;

        std::cout << "Entry: " << convertToHexString(it->first) << std::endl;
        std::cout << "  Condition: " << entryAge << " > " << mTeff;

        if (entryAge > mTeff) {
            std::cout << " (Removing)" << std::endl;
            it = mMasterPRL.erase(it);
            removedCount++;
        } else {
            std::cout << " (Keeping)" << std::endl;
            ++it;
        }
    }

    std::cout << "Total revocations removed: " << removedCount << std::endl;
    std::cout << "Remaining entries in PRL: " << mMasterPRL.size() << std::endl;
    std::cout << "===================================\n" << std::endl;
}