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
    ItsG5Service::initialize();

    mBackend.reset(new vanetza::security::BackendCryptoPP());
    std::cout << "Backend created: " << (mBackend ? "Yes" : "No") << std::endl;

    if (mBackend) {
        mKeyPair = mBackend->generate_key_pair();
        mSignedCert = GenerateRoot(mKeyPair);
        mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, mSignedCert));
        std::cout << "Key pair and root cert successfully generated." << std::endl;
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    mCrlGenInterval = 1.0;
    mRevocationInterval = 5.0;
    scheduleAt(simTime() + mCrlGenInterval, new cMessage("triggerCRLGen"));
    scheduleAt(simTime() + mRevocationInterval, new cMessage("triggerRevocation"));
}

void RevocationAuthorityService::indicate(const vanetza::btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (packet) {
        EnrollmentRequest* enrollmentRequest = dynamic_cast<EnrollmentRequest*>(packet);
        if (enrollmentRequest) {
            handleEnrollmentRequest(enrollmentRequest);
            delete enrollmentRequest;
            return;
        }
        delete packet;
    } else {
        std::cout << "Received packet is nullptr. Ignoring." << std::endl;
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
            std::cout << "CRL message sent. Revoked certificates: " << mMasterCRL.size() << std::endl;
        } else {
            std::cerr << "No network interface available for channel " << channel << std::endl;
        }
    }
}

// void RevocationAuthorityService::trigger()
// {
//     Enter_Method("trigger");
//     using namespace vanetza;

//     static const vanetza::ItsAid crl_its_aid = 622;
//     auto& mco = getFacilities().get_const<MultiChannelPolicy>();
//     auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

//     for (auto channel : mco.allChannels(crl_its_aid)) {
//         auto network = networks.select(channel);
//         if (network) {
//             btp::DataRequestB req;
//             req.destination_port = host_cast(getPortNumber(channel));
//             req.gn.transport_type = geonet::TransportType::SHB;
//             req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
//             req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
//             req.gn.its_aid = crl_its_aid;

//             std::vector<vanetza::security::Certificate> revokedCertificates = generateDummyRevokedCertificates(0);
//             CRLMessage* crlMessage = createAndPopulateCRL(revokedCertificates);
//             request(req, crlMessage, network.get());
//             // std::cout << "CRL message sent." << std::endl;
//         } else {
//             std::cerr << "No network interface available for channel " << channel << std::endl;
//         }
//     }

//     // Schedule the next trigger
//     scheduleAt(simTime() + mCrlGenInterval, new cMessage("triggerEvent"));
// }

CRLMessage* RevocationAuthorityService::createAndPopulateCRL()
{
    CRLMessage* crlMessage = new CRLMessage("CRL");

    crlMessage->setMTimestamp(omnetpp::simTime());
    crlMessage->setMRevokedCertificatesArraySize(mMasterCRL.size());

    for (size_t i = 0; i < mMasterCRL.size(); ++i) {
        crlMessage->setMRevokedCertificates(i, mMasterCRL[i]);
    }

    crlMessage->setMSignerCertificate(mSignedCert);

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

void RevocationAuthorityService::handleEnrollmentRequest(EnrollmentRequest* request)
{
    std::cout << "Processing EnrollmentRequest from vehicle: " << request->getVehicleId() << std::endl;

    // Save the public key and vehicle ID in variables
    vanetza::security::ecdsa256::PublicKey& vehiclePublicKey = request->getPublicKey();
    vanetza::security::ecdsa256::PrivateKey privateKey = mKeyPair.private_key;
    std::string vehicleId = request->getVehicleId();

    // Generate a new pseudonym certificate for the requesting vehicle
    HashedId8 rootHash = calculate_hash(mSignedCert);
    vanetza::security::Certificate pseudonymCert = GeneratePseudonym(rootHash, privateKey, vehiclePublicKey);

    // Store the pseudonym certificate with the vehicle ID
    mIssuedCertificates[vehicleId] = pseudonymCert;

    // Send the pseudonym certificate back to the vehicle
    sendPseudonymCertificate(pseudonymCert, vehiclePublicKey, vehicleId);
}

void RevocationAuthorityService::sendPseudonymCertificate(
    vanetza::security::Certificate& pseudoCert, vanetza::security::ecdsa256::PublicKey& publicKey, std::string& vehicleId)
{
    using namespace vanetza;

    PseudonymMessage* pseudonymMessage = mPseudonymHandler->createPseudonymMessage(pseudoCert, publicKey, vehicleId);

    // Send the pseudonym message to the vehicle
    static const vanetza::ItsAid pseudonym_its_aid = 623;
    auto& mco = getFacilities().get_const<MultiChannelPolicy>();
    auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

    for (auto channel : mco.allChannels(pseudonym_its_aid)) {
        auto network = networks.select(channel);
        if (network) {
            btp::DataRequestB req;
            req.destination_port = host_cast(getPortNumber(channel));
            req.gn.transport_type = geonet::TransportType::SHB;
            req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
            req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
            req.gn.its_aid = pseudonym_its_aid;

            request(req, pseudonymMessage, network.get());
            std::cout << "Pseudonym certificate sent for vehicle " << vehicleId << std::endl;
        } else {
            std::cerr << "No network interface available for channel " << channel << std::endl;
        }
    }
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
}


// namespace artery