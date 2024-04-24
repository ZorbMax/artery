#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "artery/application/ItsG5BaseService.h"
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>
#include <set>
#include <vector>

namespace artery {

struct CustomCRL
{
    vanetza::geonet::Timestamp timeStamp;
    std::vector<vanetza::security::HashedId8> revokedCertificates;
    vanetza::security::EcdsaSignature signature;
};

class RevocationAuthorityService : public ItsG5BaseService {
public:
    void initialize() override;
    void trigger() override;

private:
    std::unique_ptr<vanetza::security::Backend> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    double mCrlGenInterval;
    std::set<vanetza::ByteBuffer> mRevokedCertIds;
    CustomCRL masterCRL;
    vanetza::security::Certificate mSignedCert;

    CRLMessage* createAndSignCRL(const std::vector<vanetza::security::Certificate>& revokedCertificates);
    vanetza::ByteBuffer createCRLMessage(const CustomCRL& crl);
    void createSignedRACertificate();
    void broadcastCRLMessage(CRLMessage* crlMessage);
};

} // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */