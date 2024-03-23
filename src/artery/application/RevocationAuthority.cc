#include "RevocationAuthority.h"
#include "CRLMessage_m.h"

Define_Module(RevocationAuthority);

void RevocationAuthority::initialize()
{
    // Initialize the CRL broadcast timer
    mCRLBroadcastTimer = new omnetpp::cMessage("CRLBroadcastTimer");
    scheduleAt(omnetpp::simTime() + par("crlBroadcastInterval"), mCRLBroadcastTimer);
}

void RevocationAuthority::trigger()
{
    // Check if it's time to broadcast the CRL
    if (mCRLBroadcastTimer->isScheduled() && omnetpp::simTime() >= mCRLBroadcastTimer->getArrivalTime()) {
        broadcastCRL();
        scheduleAt(omnetpp::simTime() + par("crlBroadcastInterval"), mCRLBroadcastTimer);
    }
}

void RevocationAuthority::broadcastCRL()
{
    // Create a CRL message with the revoked certificate IDs
    auto crlMessage = new CRLMessage();
    crlMessage->setRevokedCertificatesArraySize(mMasterCRL.size());
    size_t index = 0;
    for (const auto& certificateId : mMasterCRL) {
        crlMessage->setRevokedCertificates(index++, certificateId.to_string().c_str());
    }

    // Broadcast the CRL message
    using namespace vanetza;
    btp::DataRequestB request;
    request.destination_port = btp::ports::CRL;
    request.gn.transport_type = geonet::TransportType::SHB;
    request.gn.traffic_class.tc_id(static_cast<unsigned>(geonet::TrafficClass::DP1));
    request.gn.communication_profile = geonet::CommunicationProfile::ITS_G5;

    auto confirm = Router::request(request, crlMessage);
    if (!confirm.accepted()) {
        throw omnetpp::cRuntimeError("CRL broadcast rejected");
    }
}

void RevocationAuthority::updateMasterCRL(const std::unordered_set<vanetza::security::CertificateId>& revokedCertificates)
{
    // Update the master CRL by inserting the revoked certificates
    mMasterCRL.insert(revokedCertificates.begin(), revokedCertificates.end());
}