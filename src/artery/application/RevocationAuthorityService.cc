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
    mCrlGenInterval = par("crlGenInterval");
    mRevocationInterval = par("revocationInterval");

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
    } else if (dynamic_cast<EnrollmentRequest*>(msg)) {
        handleEnrollmentRequest(static_cast<EnrollmentRequest*>(msg));
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

void RevocationAuthorityService::generateAndSendCRL()
{
    CRLMessage* crlMessage = createAndPopulateCRL();

    btp::DataRequestB req;
    req.destination_port = host_cast(getPortNumber());
    req.gn.transport_type = geonet::TransportType::SHB;
    req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
    req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
    req.gn.its_aid = CRL_ITS_AID;

    request(req, crlMessage);

    size_t messageSize = sizeof(CRLMessage) + mMasterCRL.size() * sizeof(vanetza::security::HashedId8);
    mMetrics->recordCRLDistribution(messageSize, simTime().dbl());

    std::cout << "CRL message sent. Revoked certificates: " << mMasterCRL.size() << std::endl;
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

    size_t totalCertificates = mIssuedCertificates.size() + mMasterCRL.size();
    double currentRevocationRate = static_cast<double>(mMasterCRL.size()) / totalCertificates;

    if (currentRevocationRate >= MAX_REVOCATION_RATE) {
        std::cout << "Revocation skipped. Current rate: " << (currentRevocationRate * 100) << "% (max " << (MAX_REVOCATION_RATE * 100) << "%)" << std::endl;
        return;
    }

    auto it = mIssuedCertificates.begin();
    std::advance(it, intrand(mIssuedCertificates.size()));

    vanetza::security::HashedId8 hashedId = calculate_hash(it->second);

    if (std::find(mMasterCRL.begin(), mMasterCRL.end(), hashedId) == mMasterCRL.end()) {
        mMasterCRL.push_back(hashedId);
    }

    std::string vehicleId = it->first;
    mIssuedCertificates.erase(it);

    std::cout << "Vehicle " << vehicleId << " revoked. CRL size: " << mMasterCRL.size() << std::endl;

    mMetrics->recordCRLSize(mMasterCRL.size(), simTime().dbl());

    std::string logEntry = "REVOCATION_START," + std::to_string(simTime().dbl()) + "," + convertToHexString(hashedId);
    Logger::log(logEntry);
}

// namespace artery