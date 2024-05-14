// CRLMessage.h
#pragma once

#include <omnetpp.h>
#include <vector>
#include <vanetza/security/certificate.hpp>

class CRLMessage : public omnetpp::cPacket {
public:
    CRLMessage(const char* name = nullptr, short kind = 0);
    virtual void parsimPack(omnetpp::cCommBuffer* buffer) const override;
    virtual void parsimUnpack(omnetpp::cCommBuffer* buffer) override;

    // Getters
    omnetpp::simtime_t getTimestamp() const;
    const std::vector<vanetza::security::HashedId8>& getRevokedCertificates() const;
    const vanetza::security::EcdsaSignature& getSignature() const;
    const vanetza::security::Certificate& getSignerCertificate() const;

    // Setters
    void setRevokedCertificates(const std::vector<vanetza::security::HashedId8>& revokedCertificates);
    void setSignature(const vanetza::security::EcdsaSignature& signature);
    void setSignerCertificate(const vanetza::security::Certificate& certificate);

private:
    omnetpp::simtime_t mTimestamp;
    std::vector<vanetza::security::HashedId8> mRevokedCertificates;
    vanetza::security::EcdsaSignature mSignature;
    vanetza::security::Certificate mSignerCertificate;
};