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

void RevocationAuthorityService::initialize()
{
    CentralAuthService::initialize();

    Logger::init("active_revocations.txt");
    Logger::log("Simulation started, logger initialized");

    mMetrics = std::unique_ptr<ActiveRevocationMetrics>(new ActiveRevocationMetrics());
    mCrlGenInterval = 10.0;
    mRevocationInterval = 8.0;

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
    using namespace vanetza;

    static const vanetza::ItsAid crl_its_aid = 622;
    auto& mco = getFacilities().get_const<MultiChannelPolicy>();
    auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

    for (auto channel : mco.allChannels(crl_its_aid)) {
        auto network = networks.select(channel);
        if (network) {
            btp::DataRequestB req;
            req.destination_port = host_cast(getPortNumber(channel));
            req.gn.transport_type = geonet::TransportType::SHB;
            req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
            req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
            req.gn.its_aid = crl_its_aid;

            CRLMessage* crlMessage = createAndPopulateCRL();
            request(req, crlMessage, network.get());

            size_t messageSize = sizeof(CRLMessage) + mMasterCRL.size() * sizeof(vanetza::security::HashedId8);
            mMetrics->recordCRLDistribution(messageSize, simTime().dbl());

            std::cout << "CRL message sent. Revoked certificates: " << mMasterCRL.size() << std::endl;
        } else {
            std::cerr << "No network interface available for channel " << channel << std::endl;
        }
    }
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
        return;  // No certificates to revoke
    }

    // Select a random certificate
    auto it = mIssuedCertificates.begin();
    std::advance(it, rand() % mIssuedCertificates.size());

    // Calculate the hash of the certificate
    vanetza::security::HashedId8 hashedId = calculate_hash(it->second);

    // Add the hash to the master CRL if it's not already there
    if (std::find(mMasterCRL.begin(), mMasterCRL.end(), hashedId) == mMasterCRL.end()) {
        mMasterCRL.push_back(hashedId);
    }

    std::string vehicleId = it->first;  // Get the vehicle ID

    // Remove the certificate from mIssuedCertificates
    mIssuedCertificates.erase(it);

    std::cout << "=== REVOCATION EVENT ===" << std::endl;
    std::cout << "Vehicle " << vehicleId << " has been revoked." << std::endl;
    std::cout << "Master CRL size: " << mMasterCRL.size() << std::endl;
    std::cout << "========================" << std::endl;

    mMetrics->recordCRLSize(mMasterCRL.size(), simTime().dbl());

    std::string logEntry = "REVOCATION_START," + std::to_string(simTime().dbl()) + "," + convertToHexString(hashedId);
    Logger::log(logEntry);
}

std::vector<vanetza::security::Certificate> RevocationAuthorityService::generateDummyRevokedCertificates(size_t count)
{
    std::vector<vanetza::security::Certificate> revokedCerts;

    vanetza::security::ecdsa256::KeyPair dummyKeyPair = GenerateKey();

    for (size_t i = 0; i < count; ++i) {
        vanetza::security::Certificate dummyCert = GenerateRoot(dummyKeyPair);
        revokedCerts.push_back(dummyCert);
    }

    return revokedCerts;
}

// namespace artery