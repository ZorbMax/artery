#ifndef CENTRAL_AUTH_SERVICE_H
#define CENTRAL_AUTH_SERVICE_H

#include "PseudonymMessageHandler.h"
#include "EnrollmentRequest_m.h"
#include "artery/application/ItsG5BaseService.h"
#include "artery/application/ItsG5Service.h"
#include "vanetza/security/backend.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <omnetpp.h>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>

#include <map>
#include <memory>
#include <string>

namespace artery
{

class CentralAuthService : public ItsG5Service
{
public:
    virtual void initialize() override;
    virtual void handleMessage(omnetpp::cMessage* msg) override = 0;
    virtual void revokeRandomCertificate() = 0;

protected:
    virtual void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;
    virtual void handleEnrollmentRequest(EnrollmentRequest* request);
    virtual void sendPseudonymCertificate(
        vanetza::security::Certificate& pseudoCert, vanetza::security::ecdsa256::PublicKey& publicKey, std::string& vehicleId);

    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mRootCert;
    std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;

    std::map<std::string, vanetza::security::Certificate> mIssuedCertificates;

    double mRevocationInterval;
};

}  // namespace artery

#endif  // CENTRAL_AUTH_SERVICE_H