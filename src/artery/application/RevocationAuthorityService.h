#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "artery/application/ItsG5BaseService.h"
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate.hpp>
#include <set>

namespace artery {

class RevocationAuthorityService : public ItsG5BaseService {
public:
    void initialize() override;
    void trigger() override;

private:
    std::unique_ptr<vanetza::security::Backend> mBackend;
    vanetza::security::KeyPair mKeyPair;
    double mCrlGenInterval;
    std::set<vanetza::ByteBuffer> mRevokedCertIds;
    std::set<vanetza::ByteBuffer> mCrl;
    vanetza::security::Certificate mSignedCrl;

    void generateCrl();
    void signCrl();
    void broadcastCrl();
    std::vector<uint8_t> serializeCrl() const;
};

} // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */