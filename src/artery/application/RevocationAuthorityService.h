#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "artery/application/ItsG5BaseService.h"
#include "artery/utility/Channel.h"
#include <vanetza/security/certificate.hpp>

namespace artery
{

class RevocationAuthorityService : public ItsG5BaseService
{
public:
    void initialize() override;
    void trigger() override;
    void indicate(const vanetza::btp::DataIndication&, std::unique_ptr<vanetza::UpPacket>) override;

private:
    void generateCrl();
    void signCrl();
    void broadcastCrl();

    vanetza::security::CertificateRevocationList mCrl;
    Channel mChannel;
};

} // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */