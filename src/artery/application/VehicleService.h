#ifndef VEHICLE_SERVICE_H_
#define VEHICLE_SERVICE_H_

#include "artery/application/ItsG5BaseService.h"
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/private_key.hpp>

namespace artery
{

class VehicleService : public ItsG5BaseService
{
public:
    void initialize() override;
    void trigger() override;
    void indicate(const vanetza::btp::DataIndication&, std::unique_ptr<vanetza::UpPacket>) override;

private:
    void requestCertificate();
    void storeCertificate(const vanetza::security::Certificate& certificate);
    void createMessage();
    void signMessage(vanetza::UpPacket& message);
    void sendMessage(const vanetza::UpPacket& message);
    void receiveMessage(std::unique_ptr<vanetza::UpPacket> message);
    void verifyMessage(const vanetza::UpPacket& message);

    std::vector<vanetza::security::Certificate> mPseudonymCertificates;
    std::vector<vanetza::security::PrivateKey> mPrivateKeys;
};

} // namespace artery

#endif /* VEHICLE_SERVICE_H_ */