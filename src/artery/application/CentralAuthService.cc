#include "CentralAuthService.h"

#include "EnrollmentRequest_m.h"
#include "PseudonymMessage_m.h"
#include "certify/generate-certificate.hpp"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

using namespace artery;
using namespace vanetza;
using namespace security;
using namespace omnetpp;

namespace artery
{

void CentralAuthService::initialize()
{
    ItsG5Service::initialize();

    mBackend.reset(new vanetza::security::BackendCryptoPP());
    std::cout << "Backend created: " << (mBackend ? "Yes" : "No") << std::endl;

    if (mBackend) {
        mKeyPair = mBackend->generate_key_pair();
        mRootCert = GenerateRoot(mKeyPair);
        mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mKeyPair, mRootCert));
        std::cout << "Key pair and root cert successfully generated." << std::endl;
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    mRevocationInterval = 5.0;
}

void CentralAuthService::indicate(const vanetza::btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
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

void CentralAuthService::handleEnrollmentRequest(EnrollmentRequest* request)
{
    // std::cout << "Processing EnrollmentRequest from vehicle: " << request->getVehicleId() << std::endl;

    vanetza::security::ecdsa256::PublicKey& vehiclePublicKey = request->getPublicKey();
    vanetza::security::ecdsa256::PrivateKey privateKey = mKeyPair.private_key;
    std::string vehicleId = request->getVehicleId();

    HashedId8 rootHash = calculate_hash(mRootCert);
    vanetza::security::Certificate pseudonymCert = GeneratePseudonym(rootHash, privateKey, vehiclePublicKey);

    mIssuedCertificates[vehicleId] = pseudonymCert;
    recordCertificateIssuance(vehicleId, pseudonymCert);

    sendPseudonymCertificate(pseudonymCert, vehiclePublicKey, vehicleId);
}

void CentralAuthService::sendPseudonymCertificate(
    vanetza::security::Certificate& pseudoCert, vanetza::security::ecdsa256::PublicKey& publicKey, std::string& vehicleId)
{
    using namespace vanetza;

    PseudonymMessage* pseudonymMessage = mPseudonymHandler->createPseudonymMessage(pseudoCert, publicKey, vehicleId);

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

std::string CentralAuthService::convertToHexString(const vanetza::security::HashedId8& hashedId)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : hashedId) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

}  // namespace artery