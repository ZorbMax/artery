#include "PseudoAuthService.h"

#include "CRLMessage_m.h"
#include "EnrollmentRequest_m.h"
#include "Logger.h"
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

using namespace artery;
using namespace vanetza;
using namespace security;
using namespace omnetpp;

const double PseudoAuthService::MAX_REVOCATION_RATE = 0.30;

namespace artery
{

Define_Module(PseudoAuthService)

void PseudoAuthService::initialize()
{
    CentralAuthService::initialize();

    Logger::init("passive_revocation_log.txt");
    mMetrics = std::unique_ptr<PassiveRevocationMetrics>(new PassiveRevocationMetrics());

    mMinRevocationInterval = par("minRevocationInterval").doubleValue();
    mMaxRevocationInterval = par("maxRevocationInterval").doubleValue();
    mDropProbability = par("dropProbability").doubleValue();
    mDelayProbability = par("delayProbability").doubleValue();
    mDelayMean = par("delayMean").doubleValue();
    mDelayStdDev = par("delayStdDev").doubleValue();

    std::string mode = par("revocationMode").stdstringValue();
    if (mode == "interval") {
        mRevocationMode = RevocationMode::INTERVAL;
    } else if (mode == "burst") {
        mRevocationMode = RevocationMode::BURST;
        mBurstRevocationTimes = {1000, 2000};  // You can adjust these times as needed
    } else {
        throw cRuntimeError("Invalid revocation mode specified");
    }

    if (mRevocationMode == RevocationMode::INTERVAL) {
        scheduleNextRevocation();
    } else {
        scheduleNextBurstRevocation();
    }
}

void PseudoAuthService::finish()
{
    CentralAuthService::finish();

    mMetrics->printMetrics();
    mMetrics->exportToCSV("passive_revocation_metrics.csv");
}

void PseudoAuthService::handleEnrollmentRequest(EnrollmentRequest* request)
{
    size_t messageSize = sizeof(EnrollmentRequest);
    mMetrics->recordEnrollmentRequest(messageSize, simTime().dbl());

    std::string vehicleId = request->getVehicleId();

    if (std::find(mRevocationList.begin(), mRevocationList.end(), vehicleId) != mRevocationList.end()) {
        std::cout << "Pseudonym request denied from vehicle: " << vehicleId << std::endl;
        return;
    }

    vanetza::security::ecdsa256::PublicKey& vehiclePublicKey = request->getPublicKey();
    vanetza::security::ecdsa256::PrivateKey privateKey = mKeyPair.private_key;

    HashedId8 rootHash = calculate_hash(mRootCert);
    vanetza::security::Certificate pseudonymCert = GeneratePseudonym(rootHash, privateKey, vehiclePublicKey);

    mIssuedCertificates[vehicleId] = pseudonymCert;
    recordCertificateIssuance(vehicleId, pseudonymCert);

    generateandSendPseudo(pseudonymCert, vehiclePublicKey, vehicleId);
}

void PseudoAuthService::handleMessage(cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerRevocation") == 0) {
        if (mRevocationMode == RevocationMode::INTERVAL) {
            revokeRandomCertificate();
            scheduleNextRevocation();
        } else {
            revokeBurst();
            scheduleNextBurstRevocation();
        }
        delete msg;
    } else if (dynamic_cast<EnrollmentRequest*>(msg)) {
        handleEnrollmentRequest(static_cast<EnrollmentRequest*>(msg));
        delete msg;
    } else if (auto* pseudonymMessage = dynamic_cast<PseudonymMessage*>(msg)) {
        sendPseudonym(pseudonymMessage);
    } else {
        ItsG5Service::handleMessage(msg);
    }
}
void PseudoAuthService::revokeRandomCertificate()
{
    if (mIssuedCertificates.empty()) {
        return;
    }

    auto it = mIssuedCertificates.begin();
    std::advance(it, intrand(mIssuedCertificates.size()));
    std::string vehicleId = it->first;

    if (std::find(mRevocationList.begin(), mRevocationList.end(), vehicleId) == mRevocationList.end()) {
        mRevocationList.push_back(vehicleId);
        std::string logEntry = "REVOKE," + std::to_string(simTime().dbl()) + "," + vehicleId;
        Logger::log(logEntry);
    }
    mIssuedCertificates.erase(it);

    std::cout << "Vehicle " << vehicleId << " revoked. CRL size: " << mRevocationList.size() << std::endl;
}

void PseudoAuthService::generateandSendPseudo(
    vanetza::security::Certificate& pseudoCert, vanetza::security::ecdsa256::PublicKey& publicKey, std::string& vehicleId)
{
    PseudonymMessage* pseudonymMessage = mPseudonymHandler->createPseudonymMessage(pseudoCert, publicKey, vehicleId);

    size_t messageSize = sizeof(PseudonymMessage);
    mMetrics->recordPseudonymMessage(messageSize, simTime().dbl());

    double rand = uniform(0, 1);
    if (rand < mDropProbability) {
        delete pseudonymMessage;
        std::cout << "Pseudonym certificate dropped for vehicle: " << vehicleId << std::endl;
        return;
    } else if (rand < mDropProbability + mDelayProbability) {
        simtime_t delay = std::abs(normal(mDelayMean, mDelayStdDev));
        scheduleAt(simTime() + delay, pseudonymMessage);
        std::cout << "Pseudonym certificate delayed by " << delay << "s for vehicle: " << vehicleId << std::endl;
        return;
    }

    sendPseudonym(pseudonymMessage);
}

void PseudoAuthService::sendPseudonym(PseudonymMessage* pseudonymMessage)
{
    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = 622;

    request(req, pseudonymMessage);
    std::cout << "Pseudonym certificate sent for vehicle: " << pseudonymMessage->getPayload() << std::endl;
}

void PseudoAuthService::scheduleNextRevocation()
{
    simtime_t nextRevocation = uniform(mMinRevocationInterval, mMaxRevocationInterval);
    scheduleAt(simTime() + nextRevocation, new cMessage("triggerRevocation"));
}

void PseudoAuthService::revokeBurst()
{
    int burstSize = 7;

    for (int i = 0; i < burstSize; ++i) {
        if (mIssuedCertificates.empty()) {
            break;
        }
        revokeRandomCertificate();
    }
}

void PseudoAuthService::scheduleNextBurstRevocation()
{
    simtime_t nextBurstTime = -1;
    for (const auto& burstTime : mBurstRevocationTimes) {
        if (burstTime > simTime()) {
            nextBurstTime = burstTime;
            break;
        }
    }

    if (nextBurstTime != -1) {
        scheduleAt(nextBurstTime, new cMessage("triggerRevocation"));
    }
}

}  // namespace artery