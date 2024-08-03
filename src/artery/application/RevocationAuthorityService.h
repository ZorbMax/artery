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
    void sendCRL(CRLMessage* crlMessage);

private:
    std::unique_ptr<ActiveRevocationMetrics> mMetrics;
    std::vector<vanetza::security::HashedId8> mMasterCRL;

    omnetpp::simtime_t mCrlGenInterval;
    omnetpp::simtime_t mRevocationInterval;

    static const double MAX_REVOCATION_RATE;
    static const vanetza::ItsAid CRL_ITS_AID;
};

}  // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */