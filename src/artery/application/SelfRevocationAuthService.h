#ifndef SELF_REVOCATION_AUTH_SERVICE_H_
#define SELF_REVOCATION_AUTH_SERVICE_H_

#include "CentralAuthService.h"
#include "HBMessage_m.h"
#include "SelfRevocationMetrics.h"
#include "Logger.h"

#include <map>

namespace artery
{

class SelfRevocationAuthService : public CentralAuthService
{
public:
    void initialize() override;
    void handleMessage(omnetpp::cMessage* msg) override;
    void finish() override;

protected:
    void revokeRandomCertificate() override;
    void recordCertificateIssuance(const std::string& vehicleId, const vanetza::security::Certificate& cert) override;

private:
    HBMessage* createAndPopulateHeartbeat();
    void generateAndSendHeartbeat();
    void removeExpiredRevocations();

    std::unique_ptr<SelfRevocationMetrics> mMetrics;
    std::set<std::string> mActiveVehicles;
    std::map<vanetza::security::HashedId8, double> mMasterPRL;
    double mHeartbeatInterval;
    double mTv;
    double mTeff;
    omnetpp::cMessage* mTriggerMessage;
};

}  // namespace artery

#endif /* SELF_REVOCATION_AUTH_SERVICE_H_ */