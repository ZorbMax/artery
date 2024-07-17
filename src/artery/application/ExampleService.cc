//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//
#include "ExampleService.h"

#include "artery/traci/VehicleController.h"
#include "certify/generate-key.hpp"
#include "tools/PublicKey.h"
#include "certify/generate-root.hpp"
#include "V2VMessage_m.h"

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <omnetpp/cpacket.h>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/btp/data_indication.hpp>
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

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "CertificateManager.h"
#include "RevocationAuthorityService.h"
#include "V2VMessageHandler.h"
#include "V2VMessage_m.h"
#include "artery/networking/GeoNetPacket.h"
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"

#include <arpa/inet.h>
#include <omnetpp.h>
#include <vanetza/btp/data_indication.hpp>
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
#include <memory>
#include <vector>


#include <string>

using namespace omnetpp;
using namespace vanetza;
using namespace CryptoPP;
using namespace boost::archive::iterators;

namespace artery
{

static const simsignal_t scSignalCamReceived = cComponent::registerSignal("CamReceived");

Define_Module(ExampleService)

ExampleService::ExampleService()
{
}

ExampleService::~ExampleService()
{
    cancelAndDelete(m_self_msg);
}

void ExampleService::indicate(const btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
    Enter_Method("indicate");

    if (packet) {
        // Check if the message is a CRL message
        CRLMessage* crlMessage = dynamic_cast<CRLMessage*>(packet);
        if (crlMessage) {
            std::cout << "Received a CRLMessage. Processing..." << std::endl;
            handleCRLMessage(crlMessage);
            delete crlMessage;
            return;
        }

        // Check if the message is a V2V message
        V2VMessage* v2vMessage = dynamic_cast<V2VMessage*>(packet);
        if (v2vMessage) {
            std::cout << "Received a V2VMessage. Processing..." << std::endl;

            // Extract the certificate from the V2V message
            const vanetza::security::Certificate& cert = v2vMessage->getCertificate();

            // Check if the certificate is valid
            if (!mCertificateManager->verifyCertificate(cert)) {
                std::cout << "Invalid certificate. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

            // Check if the certificate is revoked
            vanetza::security::HashedId8 certHash = calculate_hash(cert);
            if (mCertificateManager->isRevoked(certHash)) {
                std::cout << "Certificate is revoked. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

            // Verify the signature of the V2V message
            if (!mV2VHandler->verifyV2VSignature(v2vMessage)) {
                std::cout << "Invalid signature. Dropping message." << std::endl;
                discardMessage(v2vMessage);
                return;
            }

            // Process the valid and non-revoked V2V message
            processMessage(v2vMessage);
            return;
        }

		// Check if the message is a Pseudonym request message
        PseudonymMessage* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet);
        if (boolPseudo && pseudonymMessage && std::strstr(pseudonymMessage->getPayload(), "This is a pseudonym response") != nullptr) {
			// TODO verify if cert is the one from pseudonym provider
            //if (!mPseudonymHandler->verifyPseudonymSignature(pseudonymMessage)) {
        	//    std::cout << "Pseudonym message signature verification failed." << std::endl;
        	//    return;
    		//}
            std::string payload = pseudonymMessage->getPayload();
            size_t dot = payload.find(".");
            std::string id;
            if (dot != std::string::npos) {
                // Cut the string after the delimiter
                id = payload.substr(dot + 1);
            }
            if(id == mId){
                std::cout << "pseudo processing" << mId << std::endl;
                vanetza::security::Certificate cert = pseudonymMessage->getPseudonym();
                mCRLHandler = std::unique_ptr<CRLMessageHandler>(new CRLMessageHandler(mBackend.get(), mKeyPair, cert));
                mV2VHandler = std::unique_ptr<V2VMessageHandler>(new V2VMessageHandler(mBackend.get(), mKeyPair, cert));
                mCertVector.push_back(cert);
                boolPseudo = false;
            }
        }else{
            auto& vehicle = getFacilities().get_const<traci::VehicleController>();
            std::string id = vehicle.getVehicleId();
            size_t dot = id.find(".");
            if (dot != std::string::npos) {
                // Cut the string after the delimiter
                id = id.substr(dot + 1);
            }
            EV_INFO << "packet indication on channel " << net.channel << "\n";
            std::string content = packet->getName();
            std::string tag;
            std::string data;
            // std::cout << "Vehicle received " << id  << " : " << content << std::endl;
            // std::cout << "enroll content : "<< content << std::endl;
            size_t pos = content.find("|");
            if (pos != std::string::npos) {
                // std::cout << "enroll received "<< id << std::endl;
                // Cut the string after the delimiter
                tag = content.substr(0, pos);
                data = content.substr(pos + 1);
                // std::cout << "tag = " << tag << "\n";
                pos = tag.find("-");
                std::string target_id = "-1";
                std::string request;
                // Check if the delimiter was found
                if (pos != std::string::npos) {
                    // Cut the string after the delimiter
                    request = tag.substr(pos + 1);
                    target_id = tag.substr(0, pos);
                    // Output the cut string
                } else {
                    // std::cout << "Delimiter not found in the string." << std::endl;
                }
                // std::cout << "Check" << id << "=" << target_id << "\n";
                if (id == target_id && request == "enrollrespond") {
                    // std::cout << "enroll processing"<< std::endl;
                    typedef transform_width<binary_from_base64<std::string::const_iterator>, 8, 6> base64_decoder;
                    std::string decoded_data(base64_decoder(data.begin()), base64_decoder(data.end()));
                    std::cout << "Vehicle enrolled " << id << std::endl;
                    std::istringstream iss(decoded_data);
                    vanetza::InputArchive ar(iss);
                    vanetza::security::Certificate cert;
                    deserialize(ar, cert);
                    mCertificate = cert;
                    mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), mRootKeyPair, mCertificate));
                }
            }
        }
    }
    delete (packet);
}

void ExampleService::initialize()
{
    ItsG5Service::initialize();

    mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
    mCertificateManager = std::unique_ptr<CertificateManager>(new CertificateManager());

    boolPseudo = true;
    boolEnroll = true;

    auto& vehicle = getFacilities().get_const<traci::VehicleController>();
    mId = vehicle.getVehicleId();
    size_t dot = mId.find(".");
    if (dot != std::string::npos) {
        // Cut the string after the delimiter
        mId = mId.substr(dot + 1);
    }

    std::cout << "VehicleService initialized: " << mId << std::endl;
}

void ExampleService::finish()
{
    // you could record some scalars at this point
    ItsG5Service::finish();
}

void ExampleService::handleMessage(cMessage* msg)
{
    Enter_Method("handleMessage");

    if (msg == m_self_msg) {
        std::cout << "Self message\n";
        EV_INFO << "self message\n";
    }
}

void ExampleService::handleCRLMessage(CRLMessage* crlMessage)
{
    if (!mCRLHandler->verifyCRLSignature(crlMessage)) {
        std::cout << "CRL message signature verification failed." << std::endl;
        return;
    }

    std::vector<vanetza::security::HashedId8> revokedCertificates;
    for (unsigned int i = 0; i < crlMessage->getMRevokedCertificatesArraySize(); ++i) {
        revokedCertificates.push_back(crlMessage->getMRevokedCertificates(i));
    }
    mCertificateManager->updateLocalCRL(revokedCertificates);

    std::cout << "CRL message processed successfully." << std::endl;
}

void ExampleService::discardMessage(cPacket* packet)
{
    delete packet;  // Simple way to discard the message
    std::cout << "Message discarded." << std::endl;
}

void ExampleService::processMessage(V2VMessage* v2vMessage)
{
    // Implement V2V message processing logic
    std::cout << "Processing V2V message..., payload: " << v2vMessage->getPayload() << std::endl;
    // Process the message as needed
}

void ExampleService::trigger()
{
    Enter_Method("trigger");

    // use an ITS-AID reserved for testing purposes
    static const vanetza::ItsAid example_its_aid = 16480;

    auto& mco = getFacilities().get_const<MultiChannelPolicy>();
    auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

    //std::vector<int>::iterator it;
    //it = std::find(enrolledVectorr.begin(), enrolledVectorr.end(), std::stoi(mId));

    for (auto channel : mco.allChannels(example_its_aid)) {
        auto network = networks.select(channel);
        if (network) {
            btp::DataRequestB req;
            // use same port number as configured for listening on this channel
            req.destination_port = host_cast(getPortNumber(channel));
            req.gn.transport_type = geonet::TransportType::SHB;
            req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP3));
            req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
            req.gn.its_aid = example_its_aid;

            if (boolEnroll) {
                mRootKeyPair = GenerateKey();
                const vanetza::security::ecdsa256::PublicKey public_key = mRootKeyPair.public_key;
                uint8_t* buffer = static_cast<uint8_t*>(malloc(dataSize));
                serializePublicKey(public_key, buffer);

                std::string tag = mId + "-enrollrequest";
                std::string content = createPacket(tag, buffer);

                const char* content_cstr = content.c_str();
                cPacket* packet = new cPacket(content_cstr);
                packet->setByteLength(42);

                // send packet on specific network interface
                request(req, packet, network.get());
                boolEnroll = false;
            } else if (boolPseudo){
                mKeyPair = GenerateKey();
                vanetza::security::ecdsa256::PublicKey public_key = mKeyPair.public_key;
                PseudonymMessage* pseudonymMessage = mPseudonymHandler->createPseudonymMessage(public_key, mId);

                // send packet on specific network interface
                request(req, pseudonymMessage, network.get());
            }else{
                if(!mCertVector.empty()){
                    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());
                    vanetza::security::Certificate cert = mCertVector[0];
                    for (const auto& restriction : cert.validity_restriction) {
                        if (auto start_end = boost::get<StartAndEndValidity>(&restriction)) {
                            // Accessing end_validity
                            auto end_validity = start_end->end_validity;
                            if(end_validity < convert_time32(time_now)){
                                std::cout << "new pseudo" << std::endl;
                                std::cout << mId << std::endl;
                                mCertVector.erase(mCertVector.begin());
                                boolPseudo = true;
                            }
                        }
                    }
                }
                V2VMessage* v2vMessage = mV2VHandler->createV2VMessage();
                request(req, v2vMessage, network.get());
                std::cout << "V2V message sent." << std::endl;
            }

        } else {
            EV_ERROR << "No network interface available for channel " << channel << "\n";
        }
    }
}

void ExampleService::receiveSignal(cComponent* source, simsignal_t signal, cObject*, cObject*)
{
    Enter_Method("receiveSignal");

    if (signal == scSignalCamReceived) {
        auto& vehicle = getFacilities().get_const<traci::VehicleController>();
        EV_INFO << "Vehicle " << vehicle.getVehicleId() << " received a CAM in sibling serivce\n";
    }
}

}  // namespace artery
