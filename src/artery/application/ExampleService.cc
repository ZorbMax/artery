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
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>

#include "ExampleService.h"
#include "artery/traci/VehicleController.h"
#include <omnetpp/cpacket.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/btp/ports.hpp>
#include <string>
#include "certify/generate-key.hpp"
#include "tools/PublicKey.h"

using namespace omnetpp;
using namespace vanetza;
using namespace CryptoPP;
using namespace boost::archive::iterators;

std::vector<int> enrolledVectorr;
std::vector<vanetza::security::Certificate> certVector;
std::vector<vanetza::security::ecdsa256::PrivateKey> privateKeyVector;

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
	if (packet->getByteLength() == 42 || true) {
		auto& vehicle = getFacilities().get_const<traci::VehicleController>();
		std::string id = vehicle.getVehicleId();
		size_t dot = id.find(".");
		if (dot != std::string::npos) {
			// Cut the string after the delimiter
			id = id.substr(dot+1);
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
			tag = content.substr(0,pos);
			data = content.substr(pos+1);
			//std::cout << "tag = " << tag << "\n";
			pos = tag.find("-");
			std::string target_id = "-1";
			std::string request;
			// Check if the delimiter was found
			if (pos != std::string::npos) {
				// Cut the string after the delimiter
				request = tag.substr(pos+1);
				target_id = tag.substr(0, pos);
				// Output the cut string
				//std::cout << "Cut String car: " << request << "-" << target_id <<std::endl;
			} else {
				//std::cout << "Delimiter not found in the string." << std::endl;
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
				certVector.push_back(cert);
			}
		}
	}
	delete(packet);
}

void ExampleService::initialize()
{
	ItsG5Service::initialize();

	auto& vehicle = getFacilities().get_const<traci::VehicleController>();
	const std::string id = vehicle.getVehicleId();
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

void ExampleService::trigger()
{
	Enter_Method("trigger");

	// use an ITS-AID reserved for testing purposes
	static const vanetza::ItsAid example_its_aid = 16480;

	auto& mco = getFacilities().get_const<MultiChannelPolicy>();
	auto& networks = getFacilities().get_const<NetworkInterfaceTable>();

	auto& vehicle = getFacilities().get_const<traci::VehicleController>();
	std::string id = vehicle.getVehicleId();

	size_t dot = id.find(".");
	if (dot != std::string::npos) {
		// Cut the string after the delimiter
		id = id.substr(dot+1);
	}

	std::vector<int>::iterator it;
	it = std::find(enrolledVectorr.begin(), enrolledVectorr.end(), std::stoi(id));

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
			if (it == enrolledVectorr.end()){
				ecdsa256::KeyPair key_pair = GenerateKey();
				const vanetza::security::ecdsa256::PublicKey public_key = key_pair.public_key;
				privateKeyVector.push_back(key_pair.private_key);
				uint8_t* buffer = static_cast<uint8_t*>(malloc(dataSize));
				serializePublicKey(public_key, buffer);

				std::string tag = id  + "-enrollrequest";
				std::string content = createPacket(tag, buffer);
			
				const char* content_cstr = content.c_str();
				cPacket* packet = new cPacket(content_cstr);
				packet->setByteLength(42);

				// send packet on specific network interface
				request(req, packet, network.get());
				enrolledVectorr.push_back(std::stoi(id));
				// std::cout << "enroll request sent " << id <<std::endl;
			}else{
				ecdsa256::KeyPair key_pair = GenerateKey();
				const vanetza::security::ecdsa256::PublicKey public_key = key_pair.public_key;
				privateKeyVector.push_back(key_pair.private_key);
				uint8_t* buffer = static_cast<uint8_t*>(malloc(dataSize));
				serializePublicKey(public_key, buffer);

				std::string tag = id  + "-pseudorequest";
				std::string content = createPacket(tag, buffer);

				const char* content_cstr = content.c_str();
				cPacket* packet = new cPacket(content_cstr);
				packet->setByteLength(42);

				// send packet on specific network interface
				request(req, packet, network.get());
				enrolledVectorr.push_back(std::stoi(id));
				// std::cout << "enroll request sent " << id <<std::endl;
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

} // namespace artery
