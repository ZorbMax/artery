#pragma once

#include <omnetpp.h>
#include <vector>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/asn1/asn1c_conversion.hpp>

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
    void setSignature(const vanetza::security::Signature& signature);
    void setSignerCertificate(const vanetza::security::Certificate& certificate);

    // ASN.1 encoding methods
    std::string encode() const;
    std::size_t size() const;
    using asn1c_type = vanetza::asn1::CrlMessage;

private:
    omnetpp::simtime_t mTimestamp;
    std::vector<vanetza::security::HashedId8> mRevokedCertificates;
    vanetza::security::EcdsaSignature mSignature;
    vanetza::security::Certificate mSignerCertificate;
};
