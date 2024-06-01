#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "CRLMessage_m.h"
#include "artery/application/ItsG5BaseService.h"
#include "artery/application/ItsG5Service.h"

#include <omnetpp.h>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>

#include <set>
#include <vector>

namespace artery
{
class RevocationAuthorityService : public ItsG5Service
{
public:
    void initialize() override;
    void trigger() override;

private:
    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    omnetpp::cMessage* mTriggerMessage;
    double mCrlGenInterval;
    std::set<vanetza::ByteBuffer> mRevokedCertIds;
    vanetza::security::Certificate mSignedCert;

    CRLMessage* createAndPopulateCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates);
};

}  // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */
