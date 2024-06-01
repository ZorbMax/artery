#ifndef CRL_MESSAGE_H_
#define CRL_MESSAGE_H_

#include <omnetpp.h>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signature.hpp>

#include <vector>

class CRLMessage : public omnetpp::cPacket
{
public:
    CRLMessage(const char* name = nullptr, short kind = 0);

    // Getters and Setters
    omnetpp::simtime_t getTimestamp() const;
    void setTimestamp(omnetpp::simtime_t timestamp);

    const std::vector<vanetza::security::HashedId8>& getRevokedCertificates() const;
    void setRevokedCertificates(const std::vector<vanetza::security::HashedId8>& revokedCertificates);

    const vanetza::security::EcdsaSignature& getSignature() const;
    void setSignature(const vanetza::security::EcdsaSignature& signature);

    const vanetza::security::Certificate& getSignerCertificate() const;
    void setSignerCertificate(const vanetza::security::Certificate& certificate);

    // Serialization and Deserialization methods
    std::string serializePayload() const;
    std::string serializeCRL() const;
    void deserializeCRL(const std::string& data);

private:
    omnetpp::simtime_t mTimestamp;
    std::vector<vanetza::security::HashedId8> mRevokedCertificates;
    vanetza::security::EcdsaSignature mSignature;
    vanetza::security::Certificate mSignerCertificate;
};

#endif /* CRL_MESSAGE_H_ */