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

#include "RsuExample.h"
#include "artery/traci/VehicleController.h"
#include <omnetpp/cpacket.h>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/btp/ports.hpp>
#include <vanetza/security/certificate.hpp>

using namespace omnetpp;
using namespace vanetza;
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
		std::cout << "RSU received : " << *packet << "\n";
		security::Certificate cert;

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

	/// use an ITS-AID reserved for testing purposes
	/*static const vanetza::ItsAid example_its_aid = 16480;

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

			cPacket* packet = new cPacket("RSU send packet");
			packet->setByteLength(42);

			// send packet on specific network interface
			request(req, packet, network.get());
		} else {
			EV_ERROR << "No network interface available for channel " << channel << "\n";
		}
	}*/
}

void RsuExample::receiveSignal(cComponent* source, simsignal_t signal, cObject*, cObject*)
{
	Enter_Method("receiveSignal");
}

} // namespace artery
