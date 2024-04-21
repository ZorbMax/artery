#ifndef PSEUDONYM_PROVIDER_SERVICE_H_
#define PSEUDONYM_PROVIDER_SERVICE_H_

#include "artery/application/ItsG5BaseService.h"
#include <vanetza/security/certificate.hpp>

namespace artery
{

class PseudonymProviderService : public ItsG5BaseService
{
public:
    void initialize() override;
    void trigger() override;
    void indicate(const vanetza::btp::DataIndication&, std::unique_ptr<vanetza::UpPacket>) override;

private:
    vanetza::security::Certificate issueCertificate();
    //void manageCertificates();

    std::vector<vanetza::security::Certificate> mIssuedCertificates;
};

} // namespace artery

#endif /* PSEUDONYM_PROVIDER_SERVICE_H_ */