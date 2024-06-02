#ifndef VEHICLE_CRLSERVICE_H
#define VEHICLE_CRLSERVICE_H

#include "CRLMessageHandler.h"
#include "CRLMessage_m.h"
#include "CertificateManager.h"
#include "ItsG5Service.h"
#include "V2VMessageHandler.h"
#include "vanetza/security/backend.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <omnetpp.h>

#include <memory>

namespace artery
{

class VehicleCRLService : public ItsG5Service
{
protected:
    virtual void initialize() override;
    virtual void handleMessage(omnetpp::cMessage* msg) override;
    virtual void indicate(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet, const NetworkInterface& net) override;

private:
    void handleCRLMessage(CRLMessage* crlMessage);
    void processMessage(V2VMessage* v2vMessage);
    void discardMessage(omnetpp::cPacket* packet);
    void trigger() override;

    std::unique_ptr<vanetza::security::BackendCryptoPP> mBackend;
    vanetza::security::ecdsa256::KeyPair mKeyPair;
    vanetza::security::Certificate mCertificate;
    std::unique_ptr<CertificateManager> mCertificateManager;
    std::unique_ptr<CRLMessageHandler> mCRLHandler;
    std::unique_ptr<V2VMessageHandler> mV2VHandler;
};

}  // namespace artery

#endif  // VEHICLE_CRLSERVICE_H
