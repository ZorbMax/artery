#ifndef REVOCATION_AUTHORITY_SERVICE_H_
#define REVOCATION_AUTHORITY_SERVICE_H_

#include "CRLMessage_m.h"
#include "EnrollmentRequest_m.h"
#include "ItsG5Service.h"
#include "PseudonymMessageHandler.h"
#include "artery/application/ItsG5BaseService.h"
#include "artery/application/ItsG5Service.h"
#include "vanetza/security/backend.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <omnetpp.h>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate.hpp>

#include <set>
#include <unordered_map>
#include <vector>

namespace artery
{
class RevocationAuthorityService : public ItsG5Service
{
protected:
    void initialize() override;
    //void trigger() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;

private:
    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    omnetpp::cMessage* mTriggerMessage;
    double mCrlGenInterval;
    double mRevocationInterval;
    std::vector<vanetza::security::HashedId8> mMasterCRL;
    vanetza::security::Certificate mSignedCert;
    std::unordered_map<std::string, vanetza::security::Certificate> mIssuedCertificates;
    std::unique_ptr<PseudonymMessageHandler> mPseudonymHandler;

    CRLMessage* createAndPopulateCRL();
    std::vector<vanetza::security::Certificate> generateDummyRevokedCertificates(size_t count);
    void handleEnrollmentRequest(EnrollmentRequest* request);
    void sendPseudonymCertificate(vanetza::security::Certificate& pseudonym, vanetza::security::ecdsa256::PublicKey& publicKey, std::string& vehicleId);
    void revokeRandomCertificate();
    void generateAndSendCRL();
    virtual void handleMessage(omnetpp::cMessage* msg) override;
};

}  // namespace artery

#endif /* REVOCATION_AUTHORITY_SERVICE_H_ */
