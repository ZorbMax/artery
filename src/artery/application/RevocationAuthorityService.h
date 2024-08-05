#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "ActiveRevocationMetrics.h"
#include "CRLMessage_m.h"
#include "CentralAuthService.h"
#include "Logger.h"

#include <vector>

namespace artery
{

class RevocationAuthorityService : public CentralAuthService
{
public:
    void initialize() override;
    void finish() override;
    void handleMessage(omnetpp::cMessage* msg) override;

protected:
    void generateAndSendCRL();
    CRLMessage* createAndPopulateCRL();
    void revokeRandomCertificate();
    void revokeBurst();
    void sendCRL(CRLMessage* crlMessage);
    void scheduleNextRevocation();
    void scheduleNextBurstRevocation();

private:
    std::unique_ptr<ActiveRevocationMetrics> mMetrics;
    std::vector<vanetza::security::HashedId8> mMasterCRL;

    omnetpp::simtime_t mCrlGenInterval;

    static const double MAX_REVOCATION_RATE;
    static const vanetza::ItsAid CRL_ITS_AID;
};

}  // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */