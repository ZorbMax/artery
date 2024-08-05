#ifndef SELF_REVOCATION_AUTH_SERVICE_H_
#define SELF_REVOCATION_AUTH_SERVICE_H_

#include "CentralAuthService.h"
#include "HBMessage_m.h"
#include "Logger.h"
#include "SelfRevocationMetrics.h"

#include <map>

namespace artery
{

class SelfRevocationAuthService : public CentralAuthService
{
public:
    void initialize() override;
    void finish() override;
    void handleMessage(omnetpp::cMessage* msg) override;

protected:
    void generateAndSendHeartbeat();
    HBMessage* createAndPopulateHeartbeat();
    void revokeRandomCertificate() override;
    void revokeBurst();
    void removeExpiredRevocations();
    void sendHeartbeat(HBMessage* hbMessage);
    void scheduleNextRevocation();
    void scheduleNextBurstRevocation();

private:
    std::unique_ptr<SelfRevocationMetrics> mMetrics;
    std::map<vanetza::security::HashedId8, double> mMasterPRL;
    std::set<std::string> mActiveVehicles;

    double mTv;
    double mTeff;
    omnetpp::simtime_t mHeartbeatInterval;

    static const double MAX_REVOCATION_RATE;
    static const vanetza::ItsAid HB_ITS_AID = 622;
};

}  // namespace artery

#endif /* SELF_REVOCATION_AUTH_SERVICE_H_ */