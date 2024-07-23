#ifndef VEHICLE_HBSERVICE_H
#define VEHICLE_HBSERVICE_H

#include "CertificateManager.h"
#include "HBMessageHandler.h"
#include "HBMessage_m.h"
#include "ItsG5Service.h"
#include "PseudonymMessageHandler.h"
#include "PseudonymMessage_m.h"
#include "V2VMessageHandler.h"
#include "vanetza/security/backend.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <omnetpp.h>

#include <memory>

namespace artery
{

class VehicleHBService : public ItsG5Service
{
protected:
    void initialize() override;
    void handleMessage(omnetpp::cMessage* msg) override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;

private:
    bool enrollmentRequestSent;
    bool enrolled;
    bool mIsRevoked;
    double mInternalClock;
    double mValidityWindow;

    void handleHBMessage(HBMessage* heartbeatMessage);
    void handlePseudonymMessage(PseudonymMessage* pseudonymMessage);
    void handleV2VMessage(V2VMessage* v2vMessage);
    void discardMessage(omnetpp::cPacket* packet);
    void trigger() override;
    void checkAutomaticRevocation(omnetpp::simtime_t messageTimestamp);
    void performSelfRevocation();

    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mPseudonymCertificate;
    std::unique_ptr<CertificateManager> mCertificateManager;
    std::unique_ptr<V2VMessageHandler> mV2VHandler;
    std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;
    std::unique_ptr<HBMessageHandler> mHBHandler;
};

}  // namespace artery

#endif  // VEHICLE_HBSERVICE_H