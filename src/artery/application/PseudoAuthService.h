#ifndef PSEUDO_AUTH_SERVICE_H
#define PSEUDO_AUTH_SERVICE_H

#include "CRLMessage_m.h"
#include "CentralAuthService.h"

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
    void revokeRandomId();

private:
    std::vector<std::string> mRevocationList;

    omnetpp::simtime_t mRevocationInterval;

    static const double MAX_REVOCATION_RATE;
};

}  // namespace artery

#endif  //PSEUDO_AUTH_SERVICE_H