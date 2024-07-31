#ifndef VEHICLE_CRLSERVICE_H
#define VEHICLE_CRLSERVICE_H

#include "Logger.h"
#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
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

class VehiclePassiveService : public ItsG5Service
{
public:
    enum class VehicleState {
        NOT_ENROLLED,
        ENROLLMENT_REQUESTED,
        ENROLLED
    };

protected:
    void initialize() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;
    void trigger() override;
    void handleMessage(omnetpp::cMessage* msg) override;

private:
    void handlePseudonymMessage(PseudonymMessage* pseudonymMessage);
    void handleV2VMessage(V2VMessage* v2vMessage);
    bool isRevoked(const vanetza::security::Certificate& certificate) const;
    bool checkEnrolled();
    void sendEnrollmentRequest();
    void sendV2VMessage();
    std::string convertToHexString(const vanetza::security::HashedId8& hashedId);

    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mPseudonymCertificate;
    vanetza::security::Time32 mPseudonymTime;
    std::unique_ptr<V2VMessageHandler> mV2VHandler;
    std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;
    
    VehicleState mState = VehicleState::NOT_ENROLLED;
    std::vector<vanetza::security::HashedId8> mLocalCRL;

    static const vanetza::ItsAid ENROLLMENT_ITS_AID;
    static const vanetza::ItsAid V2V_ITS_AID;
};

}  // namespace artery

#endif  // VEHICLE_PASSIVESERVICE_H
