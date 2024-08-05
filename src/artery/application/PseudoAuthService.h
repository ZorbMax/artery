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
    void revokeRandomCertificate();
    void scheduleNextRevocation();
    void scheduleNextBurstRevocation();
    void revokeBurst();
    void sendPseudonym(PseudonymMessage* pseudonymMessage);
    void generateandSendPseudo(vanetza::security::Certificate& pseudoCert, vanetza::security::ecdsa256::PublicKey& publicKey, std::string& vehicleId);

private:
    std::vector<std::string> mRevocationList;

    omnetpp::simtime_t mRevocationInterval;

    static const double MAX_REVOCATION_RATE;
};

}  // namespace artery

#endif  // PSEUDO_AUTH_SERVICE_H