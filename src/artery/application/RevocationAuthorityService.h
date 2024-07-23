#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "CentralAuthService.h"
#include "CRLMessage_m.h"
#include <vector>

namespace artery
{

class RevocationAuthorityService : public CentralAuthService
{
public:
    void initialize() override;
    void handleMessage(omnetpp::cMessage* msg) override;

protected:
    void revokeRandomCertificate() override;

private:
    void generateAndSendCRL();
    CRLMessage* createAndPopulateCRL();
    std::vector<vanetza::security::Certificate> generateDummyRevokedCertificates(size_t count);

    std::vector<vanetza::security::HashedId8> mMasterCRL;
    double mCrlGenInterval;
    omnetpp::cMessage* mTriggerMessage;
};

}  // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */