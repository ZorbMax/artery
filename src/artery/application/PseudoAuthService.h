#ifndef PSEUDO_AUTH_SERVICE_H
#define PSEUDO_AUTH_SERVICE_H

#include "ActiveRevocationMetrics.h"
#include "CRLMessage_m.h"
#include "CentralAuthService.h"
#include "Logger.h"

#include <vector>

namespace artery
{

class PseudoAuthService : public CentralAuthService
{
public:
    void initialize() override;
    void finish() override;
    void handleMessage(omnetpp::cMessage* msg) override;

protected:
    void handleEnrollmentRequest(EnrollmentRequest* request) override;
    void revokeRandomCertificate();

private:
    std::unique_ptr<ActiveRevocationMetrics> mMetrics;
    std::vector<std::string> mMasterCRL;
    
    omnetpp::simtime_t mRevocationInterval;

    static const double MAX_REVOCATION_RATE;
};

}  // namespace artery

#endif  //PSEUDO_AUTH_SERVICE_H