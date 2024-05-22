#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "CRLMessage.h"
#include "artery/application/ItsG5BaseService.h"

#include <omnetpp.h>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>

#include <set>
#include <vector>

namespace artery
{
class RevocationAuthorityService : public ItsG5BaseService
{
public:
    void initialize() override;
    // void trigger() override;

private:
    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    omnetpp::cMessage* mTriggerMessage;
    double mCrlGenInterval;
    std::set<vanetza::ByteBuffer> mRevokedCertIds;
    vanetza::security::Certificate mSignedCert;

    std::string createAndSerializeCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates);
    void broadcastCRLMessage(const std::string& serializedMessage);

protected:
    void handleMessage(omnetpp::cMessage*) override;
};

}  // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */
