#ifndef VEHICLE_CRL_SERVICE_H_
#define VEHICLE_CRL_SERVICE_H_

#include "CRLMessage_m.h"
#include "ItsG5Service.h"

#include <omnetpp.h>
#include <vanetza/btp/data_indication.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/public_key.hpp>

#include <memory>
#include <vector>

namespace artery
{

class VehicleCRLService : public ItsG5Service
{
public:
    void initialize() override;
    void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net);

    bool isRevoked(const vanetza::security::HashedId8& certificateHash);

private:
    std::unique_ptr<vanetza::security::Backend> mBackend;
    std::vector<vanetza::security::HashedId8> mLocalCRL;

    void handleCRLMessage(CRLMessage* crlMessage);
    bool verifyCRLSignature(const CRLMessage* crlMessage, const vanetza::security::ecdsa256::PublicKey& publicKey);
    void updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates);
    vanetza::security::ecdsa256::PublicKey extractPublicKey(const vanetza::security::Certificate& certificate);
};

}  // namespace artery

#endif /* VEHICLE_CRL_SERVICE_H_ */
