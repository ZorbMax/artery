#include "CRLMessage.h"

#include <vanetza/common/archives.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signature.hpp>

#include <sstream>
#include <vector>

// Include necessary namespaces
using namespace vanetza;
using namespace vanetza::security;
using namespace omnetpp;

CRLMessage::CRLMessage(const char* name, short kind) : omnetpp::cPacket(name, kind)
{
}

omnetpp::simtime_t CRLMessage::getTimestamp() const
{
    return mTimestamp;
}

const std::vector<vanetza::security::HashedId8>& CRLMessage::getRevokedCertificates() const
{
    return mRevokedCertificates;
}

const vanetza::security::EcdsaSignature& CRLMessage::getSignature() const
{
    return mSignature;
}

const vanetza::security::Certificate& CRLMessage::getSignerCertificate() const
{
    return mSignerCertificate;
}

void CRLMessage::setSignerCertificate(const vanetza::security::Certificate& certificate)
{
    mSignerCertificate = certificate;
}

void CRLMessage::setTimestamp(omnetpp::simtime_t timestamp)
{
    mTimestamp = timestamp;
}

void CRLMessage::setRevokedCertificates(const std::vector<vanetza::security::HashedId8>& revokedCertificates)
{
    mRevokedCertificates = revokedCertificates;
}

void CRLMessage::setSignature(const vanetza::security::EcdsaSignature& signature)
{
    mSignature = signature;
}

std::string CRLMessage::serializePayload() const
{
    std::ostringstream oss;

    // Serialize mTimestamp
    int64_t timestampRaw = mTimestamp.raw();
    oss.write(reinterpret_cast<const char*>(&timestampRaw), sizeof(timestampRaw));
    std::cout << "Serialized mTimestamp: " << mTimestamp << " (raw: " << timestampRaw << ")" << std::endl;

    // Serialize mRevokedCertificates
    uint32_t revokedCertificatesSize = mRevokedCertificates.size();
    oss.write(reinterpret_cast<const char*>(&revokedCertificatesSize), sizeof(revokedCertificatesSize));
    std::cout << "Serialized mRevokedCertificates size: " << revokedCertificatesSize << std::endl;
    for (const auto& certificate : mRevokedCertificates) {
        oss.write(reinterpret_cast<const char*>(certificate.data()), certificate.size());
    }

    // Serialize mSignerCertificate
    vanetza::OutputArchive ar(oss);
    vanetza::security::serialize(ar, mSignerCertificate);
    std::cout << "Serialized mSignerCertificate" << std::endl;

    return oss.str();
}

std::string CRLMessage::serializeCRL() const
{
    std::ostringstream oss;

    // Serialize payload (timestamp, revoked certificates, issuer certificate)
    std::string payloadStr = serializePayload();
    oss << payloadStr;
    std::cout << "Serialized payload size: " << payloadStr.size() << std::endl;

    // Serialize mSignature
    vanetza::OutputArchive ar(oss);
    vanetza::security::serialize(ar, mSignature);
    std::cout << "Serialized mSignature" << std::endl;

    std::string serializedCRL = oss.str();
    std::cout << "Serialized CRL size: " << serializedCRL.size() << std::endl;

    return serializedCRL;
}

void CRLMessage::deserializeCRL(const std::string& data)
{
    std::istringstream iss(data);
    vanetza::InputArchive ar(iss);

    // Deserialize payload (timestamp, revoked certificates, issuer certificate)
    int64_t timestampRaw;
    iss.read(reinterpret_cast<char*>(&timestampRaw), sizeof(timestampRaw));
    mTimestamp = omnetpp::simtime_t::fromRaw(timestampRaw);
    std::cout << "Deserialized mTimestamp: " << mTimestamp << " (raw: " << timestampRaw << ")" << std::endl;

    uint32_t revokedCertificatesSize;
    iss.read(reinterpret_cast<char*>(&revokedCertificatesSize), sizeof(revokedCertificatesSize));
    std::cout << "Deserialized mRevokedCertificates size: " << revokedCertificatesSize << std::endl;
    mRevokedCertificates.clear();
    mRevokedCertificates.reserve(revokedCertificatesSize);
    for (uint32_t i = 0; i < revokedCertificatesSize; ++i) {
        HashedId8 hashedId;
        iss.read(reinterpret_cast<char*>(hashedId.data()), hashedId.size());
        mRevokedCertificates.push_back(hashedId);
    }

    vanetza::security::deserialize(ar, mSignerCertificate);
    std::cout << "Deserialized mSignerCertificate" << std::endl;

    // Deserialize signature
    vanetza::security::deserialize(ar, mSignature, PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    std::cout << "Deserialized mSignature" << std::endl;
}
