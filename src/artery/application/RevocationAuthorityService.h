#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "artery/application/ItsG5BaseService.h"
#include "CRLMessage.h"
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>
#include <set>
#include <vector>

namespace artery {
class RevocationAuthorityService : public ItsG5BaseService {
public:
    void initialize() override;
    void trigger() override;

private:
    std::unique_ptr<vanetza::security::Backend> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    omnetpp::cMessage* mTriggerMessage;
    double mCrlGenInterval;
    std::set<vanetza::ByteBuffer> mRevokedCertIds;
    vanetza::security::Certificate mSignedCert;

    CRLMessage* createAndSignCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates);
    void createSignedRACertificate();
    void broadcastCRLMessage(CRLMessage* crlMessage);
};

} // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */