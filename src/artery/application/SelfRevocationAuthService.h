#ifndef SELF_REVOCATION_AUTH_SERVICE_H_
#define SELF_REVOCATION_AUTH_SERVICE_H_

#include "CentralAuthService.h"
#include "HBMessage_m.h"

#include <map>

namespace artery
{

class SelfRevocationAuthService : public CentralAuthService
{
public:
    void initialize() override;
    void handleMessage(omnetpp::cMessage* msg) override;

protected:
    void revokeRandomCertificate() override;

private:
    HBMessage* createAndPopulateHeartbeat();
    void generateAndSendHeartbeat();
    void removeExpiredRevocations();
    std::string convertToHexString(const vanetza::security::HashedId8& hashedId);

    std::map<vanetza::security::HashedId8, double> mMasterPRL;
    double mHeartbeatInterval;
    double mTv;
    double mTeff;
    omnetpp::cMessage* mTriggerMessage;
};

}  // namespace artery

#endif /* SELF_REVOCATION_AUTH_SERVICE_H_ */