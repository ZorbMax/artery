// CRLMessage.h
#pragma once

#include <omnetpp.h>
#include <vector>
#include <vanetza/security/certificate.hpp>

class CRLMessage : public omnetpp::cPacket
{
public:
    CRLMessage(const char* name = nullptr, short kind = 0);

    virtual CRLMessage* dup() const override;
    virtual void parsimPack(omnetpp::cCommBuffer* buffer) const override;
    virtual void parsimUnpack(omnetpp::cCommBuffer* buffer) override;

    // Getter methods for the CRL data
    omnetpp::simtime_t getTimestamp() const;
    std::vector<vanetza::security::HashedId8>& getRevokedCertificates();
    // Setter for the signature
    void setSignature(const vanetza::security::EcdsaSignature& signature);

private:
    omnetpp::simtime_t mTimestamp;
    std::vector<vanetza::security::HashedId8> mRevokedCertificates;
    vanetza::security::EcdsaSignature mSignature;
};