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
    void handleMessage(omnetpp::cMessage* msg) override;
    void finish() override;

protected:
    void revokeRandomCertificate() override;

private:
    void generateAndSendCRL();
    CRLMessage* createAndPopulateCRL();
    std::vector<vanetza::security::Certificate> generateDummyRevokedCertificates(size_t count);

    std::vector<vanetza::security::HashedId8> mMasterCRL;
    double mCrlGenInterval;
    omnetpp::cMessage* mTriggerMessage;
    std::unique_ptr<ActiveRevocationMetrics> mMetrics;
};

}  // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */