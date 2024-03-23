#ifndef REVOCATIONSERVICE_H_
#define REVOCATIONSERVICE_H_

#include "artery/application/ItsG5Service.h"
#include <unordered_set>
#include <vanetza/security/certificate.hpp>

class RevocationService : public artery::ItsG5Service {
public:
    void initialize() override;
    void receive(const vanetza::btp::DataIndication&, omnetpp::cPacket*) override;
    bool isRevoked(const vanetza::security::CertificateId&) const;

private:
    void updateLocalCRL(const std::unordered_set<vanetza::security::CertificateId>&);
    std::unordered_set<vanetza::security::CertificateId> mLocalCRL;
};

#endif /* REVOCATIONSERVICE_H_ */