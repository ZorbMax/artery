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

const double SelfRevocationAuthService::MAX_REVOCATION_RATE = 0.30;

void SelfRevocationAuthService::initialize()
{
    CentralAuthService::initialize();

    mMetrics.reset(new SelfRevocationMetrics());
    mTv = par("validityWindow").doubleValue();
    mHeartbeatInterval = par("heartbeatInterval").doubleValue();
    mMinRevocationInterval = par("minRevocationInterval").doubleValue();
    mMaxRevocationInterval = par("maxRevocationInterval").doubleValue();
    mTeff = 2 * mTv;

    mDropProbability = par("dropProbability").doubleValue();
    mDelayProbability = par("delayProbability").doubleValue();
    mDelayMean = par("delayMean").doubleValue();
    mDelayStdDev = par("delayStdDev").doubleValue();

    scheduleAt(simTime() + mHeartbeatInterval, new cMessage("triggerHeartbeat"));
    scheduleNextRevocation();

    Logger::init("simulation_log.txt");
    std::cout << "Simulation started, logger initialized" << std::endl;

    mMetrics->recordActiveVehicleCount(mIssuedCertificates.size(), simTime().dbl());
}

void SelfRevocationAuthService::scheduleNextRevocation()
{
    simtime_t nextRevocation = uniform(mMinRevocationInterval, mMaxRevocationInterval);
    scheduleAt(simTime() + nextRevocation, new cMessage("triggerRevocation"));
}

void SelfRevocationAuthService::finish()
{
    CentralAuthService::finish();

    Logger::log("Simulation ended, closing logger");
    Logger::close();

    mMetrics->exportToCSV();
    mMetrics->printMetrics();
}

void SelfRevocationAuthService::handleMessage(cMessage* msg)
{
    if (msg->isName("triggerHeartbeat")) {
        removeExpiredRevocations();
        generateAndSendHeartbeat();
        mMetrics->recordActiveVehicleCount(mActiveVehicles.size(), simTime().dbl());
        scheduleAt(simTime() + mHeartbeatInterval, msg);
    } else if (msg->isName("triggerRevocation")) {
        revokeRandomCertificate();
        scheduleNextRevocation();
        delete msg;
    } else if (auto* enrollmentRequest = dynamic_cast<EnrollmentRequest*>(msg)) {
        handleEnrollmentRequest(enrollmentRequest);
        delete msg;
    } else if (auto* hbMessage = dynamic_cast<HBMessage*>(msg)) {
        std::cout << "Sending delayed HB..." << std::endl;
        sendHeartbeat(hbMessage);
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

void SelfRevocationAuthService::sendHeartbeat(HBMessage* hbMessage)
{
    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = HB_ITS_AID;

    request(req, hbMessage);

    size_t messageSize = sizeof(HBMessage) + mMasterPRL.size() * sizeof(vanetza::security::HashedId8);
    mMetrics->recordHeartbeat(messageSize, simTime().dbl());

    std::cout << "Heartbeat message sent. Revoked certificates: " << mMasterPRL.size() << std::endl;
}

void SelfRevocationAuthService::generateAndSendHeartbeat()
{
    HBMessage* hbMessage = createAndPopulateHeartbeat();

    // Simulate network conditions
    double rand = uniform(0, 1);
    if (rand < mDropProbability) {
        delete hbMessage;
        std::cout << "Heartbeat dropped due to simulated network loss" << std::endl;
        return;
    } else if (rand < mDropProbability + mDelayProbability) {
        simtime_t delay = normal(mDelayMean, mDelayStdDev);
        scheduleAt(simTime() + delay, hbMessage);
        std::cout << "Heartbeat delayed by " << delay << " seconds" << std::endl;
        return;
    }

    sendHeartbeat(hbMessage);
}

HBMessage* SelfRevocationAuthService::createAndPopulateHeartbeat()
{
    auto* hbMessage = new HBMessage("Heartbeat");
    hbMessage->setMTimestamp(simTime());
    hbMessage->setPRLArraySize(mMasterPRL.size());

    size_t index = 0;
    for (const auto& entry : mMasterPRL) {
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
        throw omnetpp::cRuntimeError("Error: BackendCryptoPP is nullptr");
    }

    return hbMessage;
}

void SelfRevocationAuthService::revokeRandomCertificate()
{
    if (mIssuedCertificates.empty()) {
        return;
    }

    // Determine the number of certificates to revoke (1 to 5)
    int numRevocations = intrand(3) + 1;

    for (int i = 0; i < numRevocations; ++i) {
        if (mIssuedCertificates.empty()) {
            break;
        }

        // Define a range for recent enrollments (e.g., last 25% of certificates)
        size_t recentEnrollmentCount = std::max(size_t(1), mIssuedCertificates.size() / 4);

        // Select a random certificate from the recent enrollments
        auto it = mIssuedCertificates.end();
        std::advance(it, -static_cast<long>(intrand(recentEnrollmentCount) + 1));

        std::string vehicleId = it->first;
        vanetza::security::HashedId8 hashedId = calculate_hash(it->second);

        if (mMasterPRL.find(hashedId) == mMasterPRL.end()) {
            mMasterPRL[hashedId] = simTime().dbl();
            mMetrics->recordRevocation(hashedId, simTime().dbl());
        }

        mIssuedCertificates.erase(it);
        mActiveVehicles.erase(vehicleId);

        mMetrics->recordActiveVehicleCount(mActiveVehicles.size(), simTime().dbl());

        Logger::log("REVOKE," + std::to_string(simTime().dbl()) + "," + convertToHexString(hashedId));
        std::cout << "Vehicle " << vehicleId << " revoked. PRL size: " << mMasterPRL.size() << ", Active vehicles: " << mActiveVehicles.size() << std::endl;
    }
}

void SelfRevocationAuthService::removeExpiredRevocations()
{
    auto currentTime = simTime().dbl();
    auto it = mMasterPRL.begin();
    int removedCount = 0;

    while (it != mMasterPRL.end()) {
        double entryAge = currentTime - it->second;
        if (entryAge > mTeff) {
            // Logger::log("PRL_REMOVE," + std::to_string(currentTime) + "," + convertToHexString(it->first) + ",Age:" + std::to_string(entryAge));
            it = mMasterPRL.erase(it);
            removedCount++;
        } else {
            ++it;
        }
    }

    std::cout << "Removed " << removedCount << " expired revocations. Remaining in PRL: " << mMasterPRL.size() << std::endl;
}
