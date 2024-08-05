#include "PseudoAuthService.h"

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

    mRevocationInterval = par("revocationInterval");

    scheduleAt(simTime() + mRevocationInterval, new cMessage("triggerRevocation"));
}

void PseudoAuthService::finish()
{
    CentralAuthService::finish();
}

void PseudoAuthService::handleEnrollmentRequest(EnrollmentRequest* request)
{
    std::string vehicleId = request->getVehicleId();
    // std::cout << "Processing Pseudonym request from vehicle: " << vehicleId << std::endl;

    if (std::find(mRevocationList.begin(), mRevocationList.end(), vehicleId) != mRevocationList.end()) {
        // std::cout << "Pseudonym request denied from vehicle: " << vehicleId << std::endl;
        return;
    }

    vanetza::security::ecdsa256::PublicKey& vehiclePublicKey = request->getPublicKey();
    vanetza::security::ecdsa256::PrivateKey privateKey = mKeyPair.private_key;

    HashedId8 rootHash = calculate_hash(mRootCert);
    vanetza::security::Certificate pseudonymCert = GeneratePseudonym(rootHash, privateKey, vehiclePublicKey);

    mIssuedCertificates[vehicleId] = pseudonymCert;
    recordCertificateIssuance(vehicleId, pseudonymCert);

    sendPseudonymCertificate(pseudonymCert, vehiclePublicKey, vehicleId);
}

void PseudoAuthService::handleMessage(cMessage* msg)
{
    if (strcmp(msg->getName(), "triggerRevocation") == 0) {
        revokeRandomCertificate();
        scheduleAt(simTime() + mRevocationInterval, msg);
    } else if (dynamic_cast<EnrollmentRequest*>(msg)) {
        handleEnrollmentRequest(static_cast<EnrollmentRequest*>(msg));
        delete msg;
    } else {
        ItsG5Service::handleMessage(msg);
    }
}

void PseudoAuthService::revokeRandomId()
{
    if (mIssuedCertificates.empty()) {
        return;
    }

    size_t totalCertificates = mIssuedCertificates.size() + mRevocationList.size();
    double currentRevocationRate = static_cast<double>(mRevocationList.size()) / totalCertificates;

    if (currentRevocationRate >= MAX_REVOCATION_RATE) {
        std::cout << "Revocation skipped. Current rate: " << (currentRevocationRate * 100) << "% (max " << (MAX_REVOCATION_RATE * 100) << "%)" << std::endl;
        return;
    }

    auto it = mIssuedCertificates.begin();
    std::advance(it, intrand(mIssuedCertificates.size()));
    std::string vehicleId = it->first;

    if (std::find(mRevocationList.begin(), mRevocationList.end(), vehicleId) == mRevocationList.end()) {
        mRevocationList.push_back(vehicleId);
    }
    mIssuedCertificates.erase(it);

    std::cout << "Vehicle " << vehicleId << " revoked. CRL size: " << mRevocationList.size() << std::endl;
}

}  // namespace artery