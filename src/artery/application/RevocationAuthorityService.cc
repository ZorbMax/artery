#include "RevocationAuthorityService.h"

#include "CRLMessage_m.h"
#include "artery/networking/GeoNetPacket.h"
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

#include <iomanip>
#include <iostream>

using namespace artery;
using namespace vanetza::security;
using namespace omnetpp;

Define_Module(RevocationAuthorityService)

void RevocationAuthorityService::initialize()
{
    ItsG5Service::initialize();

    mBackend.reset(new vanetza::security::BackendCryptoPP());
    std::cout << "Backend created: " << (mBackend ? "Yes" : "No") << std::endl;

    if (mBackend) {
        mKeyPair = mBackend->generate_key_pair();
        mSignedCert = GenerateRoot(mKeyPair);
        std::cout << "Key pair and root cert successfully generated." << std::endl;
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    mCrlGenInterval = 5.0;
}

void RevocationAuthorityService::trigger()
{
    Enter_Method("trigger");
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

            std::vector<vanetza::security::Certificate> revokedCertificates = generateDummyRevokedCertificates(3);
            CRLMessage* crlMessage = createAndPopulateCRL(revokedCertificates);
            request(req, crlMessage, network.get());
            std::cout << "CRL message sent." << std::endl;
        } else {
            std::cerr << "No network interface available for channel " << channel << std::endl;
        }
    }
}


CRLMessage* RevocationAuthorityService::createAndPopulateCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates)
{
    // Step 1: Create a new CRLMessage object
    CRLMessage* crlMessage = new CRLMessage("CRL");

    // Step 2: Set the timestamp of the CRLMessage
    crlMessage->setMTimestamp(omnetpp::simTime());

    // Step 3: Set the size of the revoked certificates array
    crlMessage->setMRevokedCertificatesArraySize(revokedCertificates.size());

    // Step 4: Iterate over the revoked certificates and add their hashes to the array
    for (size_t i = 0; i < revokedCertificates.size(); ++i) {
        vanetza::security::HashedId8 hashedId = calculate_hash(revokedCertificates[i]);
        crlMessage->setMRevokedCertificates(i, hashedId);
    }

    // Step 5: Set the signer's certificate in the CRLMessage object
    crlMessage->setMSignerCertificate(mSignedCert);

    // Step 6: Create the signature for the CRLMessage
    if (mBackend) {
        // Collect data to sign
        vanetza::ByteBuffer dataToSign;

        // Add the timestamp
        uint64_t timestamp = static_cast<uint64_t>(crlMessage->getMTimestamp().dbl() * 1e9);  // Convert to nanoseconds
        dataToSign.insert(dataToSign.end(), reinterpret_cast<uint8_t*>(&timestamp), reinterpret_cast<uint8_t*>(&timestamp) + sizeof(timestamp));

        // Add revoked certificates hashes
        for (size_t i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
            auto& hash = crlMessage->getMRevokedCertificates(i);
            dataToSign.insert(dataToSign.end(), hash.data(), hash.data() + hash.size());
        }

        // Add the serialized signer certificate
        vanetza::ByteBuffer serializedCert = vanetza::security::convert_for_signing(crlMessage->getMSignerCertificate());
        dataToSign.insert(dataToSign.end(), serializedCert.begin(), serializedCert.end());

        // Generate the signature
        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(mKeyPair.private_key, dataToSign);
        crlMessage->setMSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return crlMessage;
}

std::vector<vanetza::security::Certificate> artery::RevocationAuthorityService::generateDummyRevokedCertificates(size_t count)
{
    std::vector<vanetza::security::Certificate> revokedCerts;

    vanetza::security::ecdsa256::KeyPair dummyKeyPair = GenerateKey();

    for (size_t i = 0; i < count; ++i) {
        vanetza::security::Certificate dummyCert = GenerateRoot(dummyKeyPair);
        revokedCerts.push_back(dummyCert);
    }

    return revokedCerts;
}