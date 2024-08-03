#include "RevocationAuthorityService.h"

#include "CRLMessage_m.h"
#include "EnrollmentRequest_m.h"
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

Define_Module(artery::RevocationAuthorityService)

using namespace artery;
using namespace vanetza;
using namespace security;
using namespace omnetpp;

const double RevocationAuthorityService::MAX_REVOCATION_RATE = 0.30;
const vanetza::ItsAid RevocationAuthorityService::CRL_ITS_AID = 622;

void RevocationAuthorityService::initialize()
{
    CentralAuthService::initialize();

    Logger::init("active_revocations.txt");
    Logger::log("Simulation started, logger initialized");

    mMetrics = std::unique_ptr<ActiveRevocationMetrics>(new ActiveRevocationMetrics());
    mCrlGenInterval = par("crlGenInterval").doubleValue();
    mRevocationInterval = par("revocationInterval").doubleValue();

    mDropProbability = par("dropProbability").doubleValue();
    mDelayProbability = par("delayProbability").doubleValue();
    mDelayMean = par("delayMean").doubleValue();
    mDelayStdDev = par("delayStdDev").doubleValue();

    scheduleAt(simTime() + mCrlGenInterval, new cMessage("triggerCRLGen"));
    scheduleAt(simTime() + mRevocationInterval, new cMessage("triggerRevocation"));
}

void RevocationAuthorityService::finish()
{
    CentralAuthService::finish();

    Logger::log("Simulation ended, closing logger");
    Logger::close();

    std::string filename = "active_revocation_crl.csv";
    mMetrics->exportToCSV(filename);
    mMetrics->printMetrics();
}

void RevocationAuthorityService::handleMessage(cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerCRLGen") == 0) {
        generateAndSendCRL();
        scheduleAt(simTime() + mCrlGenInterval, msg);
    } else if (strcmp(msg->getName(), "triggerRevocation") == 0) {
        revokeRandomCertificate();
        scheduleAt(simTime() + mRevocationInterval, msg);
    } else if (auto* enrollmentRequest = dynamic_cast<EnrollmentRequest*>(msg)) {
        handleEnrollmentRequest(enrollmentRequest);
        delete msg;
    } else if (auto* crlMessage = dynamic_cast<CRLMessage*>(msg)) {
        std::cout << "Sending delayed CRL..." << std::endl;
        sendCRL(crlMessage);
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

void RevocationAuthorityService::sendCRL(CRLMessage* crlMessage)
{
    vanetza::btp::DataRequestB req;
    req.destination_port = vanetza::host_cast(getPortNumber());
    req.gn.transport_type = vanetza::geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(vanetza::dcc::Profile::DP3));
    req.gn.communication_profile = vanetza::geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = CRL_ITS_AID;

    request(req, crlMessage);
    std::cout << "CRL message sent. Revoked certificates: " << mMasterCRL.size() << std::endl;
}

void RevocationAuthorityService::generateAndSendCRL()
{
    CRLMessage* crlMessage = createAndPopulateCRL();

    // Simulate network conditions
    double rand = uniform(0, 1);
    if (rand < mDropProbability) {
        delete crlMessage;
        std::cout << "CRL dropped due to simulated network loss" << std::endl;
        return;
    } else if (rand < mDropProbability + mDelayProbability) {
        simtime_t delay = normal(mDelayMean, mDelayStdDev);
        scheduleAt(simTime() + delay, crlMessage);
        std::cout << "CRL delayed by " << delay << " seconds" << std::endl;
        return;
    }

    size_t messageSize = sizeof(CRLMessage) + mMasterCRL.size() * sizeof(vanetza::security::HashedId8);
    mMetrics->recordCRLDistribution(messageSize, simTime().dbl());
    mMetrics->recordCRLSize(mMasterCRL.size(), simTime().dbl());

    sendCRL(crlMessage);
}

CRLMessage* RevocationAuthorityService::createAndPopulateCRL()
{
    CRLMessage* crlMessage = new CRLMessage("CRL");
    crlMessage->setMTimestamp(omnetpp::simTime());
    crlMessage->setMRevokedCertificatesArraySize(mMasterCRL.size());

    for (size_t i = 0; i < mMasterCRL.size(); ++i) {
        crlMessage->setMRevokedCertificates(i, mMasterCRL[i]);
    }

    crlMessage->setMSignerCertificate(mRootCert);

    if (mBackend) {
        vanetza::ByteBuffer dataToSign;

        uint64_t timestamp = static_cast<uint64_t>(crlMessage->getMTimestamp().dbl() * 1e9);
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

        for (size_t i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
            auto& hash = crlMessage->getMRevokedCertificates(i);
            dataToSign.insert(dataToSign.end(), hash.data(), hash.data() + hash.size());
        }

        vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(crlMessage->getMSignerCertificate());
        dataToSign.insert(dataToSign.end(), serializedCert.begin(), serializedCert.end());

        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        crlMessage->setMSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return crlMessage;
}

void RevocationAuthorityService::revokeRandomCertificate()
{
    if (mIssuedCertificates.empty()) {
        return;
    }

    // Determine the number of certificates to revoke (1 to 5)
    int numRevocations = intrand(5) + 1;

    for (int i = 0; i < numRevocations; ++i) {
        if (mIssuedCertificates.empty()) {
            break;
        }

        // Define a range for recent enrollments (e.g., last 25% of certificates)
        size_t recentEnrollmentCount = std::max(size_t(1), mIssuedCertificates.size() / 4);

        // Select a random certificate from the recent enrollments
        auto it = mIssuedCertificates.end();
        std::advance(it, -static_cast<long>(intrand(recentEnrollmentCount) + 1));

        vanetza::security::HashedId8 hashedId = calculate_hash(it->second);

        if (std::find(mMasterCRL.begin(), mMasterCRL.end(), hashedId) == mMasterCRL.end()) {
            mMasterCRL.push_back(hashedId);
        }

        std::string vehicleId = it->first;
        mIssuedCertificates.erase(it);

        std::cout << "Vehicle " << vehicleId << " revoked. CRL size: " << mMasterCRL.size() << std::endl;

        std::string logEntry = "REVOCATION_START," + std::to_string(simTime().dbl()) + "," + convertToHexString(hashedId);
        Logger::log(logEntry);
    }
}

// namespace artery