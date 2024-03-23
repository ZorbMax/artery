#ifndef REVOCATIONAUTHORITY_H_
#define REVOCATIONAUTHORITY_H_

#include "artery/application/ItsG5Service.h"
#include <unordered_set>
#include <vanetza/security/certificate.hpp>

class RevocationAuthority : public artery::ItsG5Service {
public:
    void initialize() override;
    void trigger() override;

private:
    void broadcastCRL();
    void updateMasterCRL(const std::unordered_set<vanetza::security::CertificateId>&);
    std::unordered_set<vanetza::security::CertificateId> mMasterCRL;
    omnetpp::cMessage* mCRLBroadcastTimer = nullptr;
};

#endif /* REVOCATIONAUTHORITY_H_ */