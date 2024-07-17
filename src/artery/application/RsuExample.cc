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

#include <vanetza/btp/ports.hpp>
#include <vanetza/dcc/transmission.hpp>
#include <vanetza/dcc/transmit_rate_control.hpp>
#include <vanetza/common/byte_buffer_sink.hpp>
#include <vanetza/common/serialization_buffer.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include "artery/utility/Identity.h"

#include "RsuExample.h"
#include "artery/traci/VehicleController.h"
#include <omnetpp/cpacket.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/btp/ports.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/common/archives.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <boost/archive/text_oarchive.hpp>
#include "certify/generate-key.hpp"
#include "certify/generate-root.hpp"
#include "certify/generate-certificate.hpp"
#include "tools/PublicKey.h"

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
#include <vector>
#include <string_view>
#include <random>
#include <iterator>

using namespace artery;
using namespace vanetza::security;
using namespace omnetpp;
using namespace vanetza;
using namespace CryptoPP;
using namespace boost::archive::iterators;

ecdsa256::KeyPair keyPair = GenerateKey();
const vanetza::security::Certificate rootCert = GenerateRoot(keyPair);
const HashedId8 rootHash = calculate_hash(rootCert);

ecdsa256::KeyPair pseudoKeyPair = GenerateKey();
const vanetza::security::Certificate pseudoRootCert = GenerateRoot(pseudoKeyPair);
const HashedId8 pseudoRootHash = calculate_hash(pseudoRootCert);

std::string taggedData;
ByteBuffer buf;
std::vector<int> enrolledVector;
vanetza::security::Certificate tempCert;
PseudonymMessage* tempPseudoMessage;

std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend = std::unique_ptr<vanetza::security::BackendCryptoPP>(new vanetza::security::BackendCryptoPP());
std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler = std::unique_ptr<PseudonymMessageHandler>(new PseudonymMessageHandler(mBackend.get(), pseudoKeyPair, pseudoRootCert));

std::set<vanetza::ByteBuffer> mRevokedCertIds;
vanetza::security::ecdsa256::KeyPair revocationKeyPair = mBackend->generate_key_pair();
vanetza::security::Certificate revocationRootCert = GenerateRoot(revocationKeyPair);

std::vector<vanetza::security::Certificate> pseudoCertificates;

int mCrlGenInterval = 20;
auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());
Time32 nextRevocFrame = convert_time32(time_now + std::chrono::seconds(60));
bool boolRevocation = true;
CRLMessage* crlMessage;


template<typename Iter, typename RandomGenerator>
Iter select_randomly(Iter start, Iter end, RandomGenerator& g) {
    std::uniform_int_distribution<> dis(0, std::distance(start, end) - 1);
    std::advance(start, dis(g));
    return start;
}

template<typename Iter>
Iter select_randomly(Iter start, Iter end) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    return select_randomly(start, end, gen);
}

namespace artery
{

Define_Module(RsuExample)

RsuExample::RsuExample()
{
}

RsuExample::~RsuExample()
{
	cancelAndDelete(m_self_msg);
}

void RsuExample::indicate(const btp::DataIndication& ind, cPacket* packet, const NetworkInterface& net)
{
	Enter_Method("indicate");
	
	if (packet){
		// Check if the message is a Pseudonym request message
        PseudonymMessage* pseudonymMessage = dynamic_cast<PseudonymMessage*>(packet);
        if (!boolPseudo && pseudonymMessage && std::strstr(pseudonymMessage->getPayload(), "This is a pseudonym message payload.") != nullptr) {
			std::cout << "Received a pseudonym request. Processing..." << std::endl;
			// TODO verify cert is long term cred
            //if (!mPseudonymHandler->verifyPseudonymSignature(pseudonymMessage)) {
        	//	std::cout << "Pseudonym message signature verification failed." << std::endl;
        	//	return;
    		//}
			std::string payload = pseudonymMessage->getPayload();
            size_t dot = payload.find(".");
			std::string id;
            if (dot != std::string::npos) {
                // Cut the string after the delimiter
                id = payload.substr(dot + 1);
            }
			vanetza::security::ecdsa256::PublicKey& public_key = pseudonymMessage->getPublic_key();
			tempCert = GeneratePseudonym(pseudoRootHash, pseudoKeyPair.private_key, public_key);
			boolPseudo = true;
			pseudoCertificates.push_back(tempCert);
			tempPseudoMessage = mPseudonymHandler->createPseudonymMessage(tempCert, id);
			delete pseudonymMessage;
        }else{
			// EV_INFO << "packet indication on channel " << net.channel << "\n";
			std::string content = packet->getName();
			// std::cout << "RSU received : " << content << "\n";
			std::string tag;
			const uint8_t* data = static_cast<uint8_t*>(malloc(dataSize));
			parsePacket(content, tag, data);

			size_t pos = tag.find("-");
			std::string request;
			std::string id;
			// Check if the delimiter was found
    		if (pos != std::string::npos) {
				// Cut the string after the delimiter
				request = tag.substr(pos+1);
				id = tag.substr(0, pos);
				// Output the cut string

				std::vector<int>::iterator it;
				it = std::find(enrolledVector.begin(), enrolledVector.end(), std::stoi(id));

				if(request == "enrollrequest" && it == enrolledVector.end()){
					std::cout << "enroll request " << id <<std::endl;
					vanetza::security::ecdsa256::PublicKey public_key = deserializePublicKey(data);
					const vanetza::security::Certificate cert = GenerateCertificate(rootHash, keyPair.private_key, public_key);

					// Create an output stream buffer
					std::ostringstream oss;
					// Create an OutputArchive object with the output stream buffer
					OutputArchive ao(oss);

					serialize(ao, cert);
					std::string serializedData = oss.str();

 					typedef base64_from_binary<transform_width<std::string::const_iterator, 6, 8>> base64_encoder;
					typedef transform_width<binary_from_base64<std::string::const_iterator>, 8, 6> base64_decoder;

    				// Encode the input string
    				std::string encoded_data(base64_encoder(serializedData.begin()), base64_encoder(serializedData.end()));

					std::string decoded_data(base64_decoder(encoded_data.begin()), base64_decoder(encoded_data.end()));

					tag = id  + "-enrollrespond";
					taggedData = tag + "|" + encoded_data;
					boolEnroll = true;
					enrolledVector.push_back(std::stoi(id));
				}
			}else{
				//std::cout << "Delimiter not found in the string." << std::endl;
			}
			delete(packet);
		}
	}
}

void RsuExample::initialize()
{
	ItsG5Service::initialize();
	m_self_msg = new cMessage("RSU Example Service");

	scheduleAt(simTime() + 3, m_self_msg);
}

void RsuExample::finish()
{
	// you could record some scalars at this point
	ItsG5Service::finish();
}

void RsuExample::handleMessage(cMessage* msg)
{
	Enter_Method("handleMessage");

	if (msg == m_self_msg) {
		EV_INFO << "self message\n";
	}
}


void RsuExample::trigger()
{
	Enter_Method("trigger");
	static const vanetza::ItsAid example_its_aid = 16480;

	auto& mco = getFacilities().get_const<MultiChannelPolicy>();
	auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

	for (auto channel : mco.allChannels(example_its_aid)) {
		auto network = networks.select(channel);
		if (network) {
			btp::DataRequestB req;
			// use same port number as configured for listening on this channel
			req.destination_port = host_cast(getPortNumber(channel));
			req.gn.transport_type = geonet::TransportType::SHB;
			req.gn.traffic_class.tc_id(static_cast<unsigned>(dcc::Profile::DP2));
			req.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;
			req.gn.its_aid = example_its_aid;

			if (boolEnroll){
				// const Identity* mIdentity = &getFacilities().get_const<Identity>();
				// const uint32_t id = mIdentity->application;
				const char* content_cstr = taggedData.c_str();
				cPacket* packet = new cPacket(content_cstr);
				// send packet on specific network interface
				request(req, packet, network.get());
				boolEnroll = false;
			}
			else if(boolPseudo){
				// send packet on specific network interface
				request(req, tempPseudoMessage, network.get());
				boolPseudo = false;
			}
			else{
				auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());
				if(nextRevocFrame < convert_time32(time_now) && boolRevocation){
					std::cout << "Starting revocation" <<std::endl;
					boolRevocation = false;
					std::vector<vanetza::security::Certificate> revokedCertificates;
					for (int i = 0; i < 5; ++i){
						revokedCertificates.push_back(*select_randomly(pseudoCertificates.begin(), pseudoCertificates.end()));
					}
            		crlMessage = createAndPopulateCRL(revokedCertificates);
            		request(req, crlMessage, network.get());
				}else if(nextRevocFrame < convert_time32(time_now)){ //Second rsu sending the crl then setup next frame
					boolRevocation = true;
					nextRevocFrame = convert_time32(time_now + std::chrono::seconds(mCrlGenInterval));
					request(req, crlMessage, network.get());
					std::cout << "CRL message sent." << std::endl;
				}
			}

		} else {
			EV_ERROR << "No network interface available for channel " << channel << "\n";
		}
	}
}

void RsuExample::receiveSignal(cComponent* source, simsignal_t signal, cObject*, cObject*)
{
	Enter_Method("receiveSignal");
}

CRLMessage* RsuExample::createAndPopulateCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates)
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
    crlMessage->setMSignerCertificate(revocationRootCert);

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
        vanetza::security::EcdsaSignature ecdsaSignature = mBackend->sign_data(revocationKeyPair.private_key, dataToSign);
        crlMessage->setMSignature(ecdsaSignature);
    } else {
        std::cerr << "Error: BackendCryptoPP is nullptr" << std::endl;
    }

    return crlMessage;
}

std::vector<vanetza::security::Certificate> artery::RsuExample::generateDummyRevokedCertificates(size_t count)
{
    std::vector<vanetza::security::Certificate> revokedCerts;

    vanetza::security::ecdsa256::KeyPair dummyKeyPair = GenerateKey();

    for (size_t i = 0; i < count; ++i) {
        vanetza::security::Certificate dummyCert = GenerateRoot(dummyKeyPair);
        revokedCerts.push_back(dummyCert);
    }

    return revokedCerts;
}

} // namespace artery
