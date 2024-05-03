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


#include <vector>
#include <string_view>
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

using namespace omnetpp;
using namespace vanetza;
using namespace CryptoPP;
using namespace boost::archive::iterators;

ecdsa256::KeyPair key_pair = GenerateKey();
const vanetza::security::Certificate root_cert = GenerateRoot(key_pair);
const HashedId8 root_hash = calculate_hash(root_cert);
std::string taggedData;
ByteBuffer buf;
std::vector<int> enrolledVector;
bool enroll = false;
int counter = 0;

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

	if (packet->getByteLength() == 42) {
		EV_INFO << "packet indication on channel " << net.channel << "\n";
		std::string content = packet->getName();
		//std::cout << "RSU received : " << content << "\n";
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
				const vanetza::security::Certificate cert = GenerateCertificate(root_hash, key_pair.private_key, public_key);

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
				enroll = true;
				enrolledVector.push_back(std::stoi(id));
			}
		} else {
			//std::cout << "Delimiter not found in the string." << std::endl;
		}
	}
	delete(packet);
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

			if (enroll){
				counter += 1;
				// const Identity* mIdentity = &getFacilities().get_const<Identity>();
				// const uint32_t id = mIdentity->application;
				const char* content_cstr = taggedData.c_str();
				cPacket* packet = new cPacket(content_cstr);
				// send packet on specific network interface
				request(req, packet, network.get());
				
				if (counter >= 2){
					enroll = false;
					counter = 0;
				}
			}
			//else {
				//cPacket* packet = new cPacket("RSU send packet");
				//packet->setByteLength(42);
				// send packet on specific network interface
				//request(req, packet, network.get());
			//}

		} else {
			EV_ERROR << "No network interface available for channel " << channel << "\n";
		}
	}
}

void RsuExample::receiveSignal(cComponent* source, simsignal_t signal, cObject*, cObject*)
{
	Enter_Method("receiveSignal");
}

} // namespace artery
