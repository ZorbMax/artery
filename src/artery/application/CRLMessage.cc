#include "CRLMessage.h"

#include <vanetza/common/archives.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signature.hpp>

#include <sstream>
#include <vector>

// Include necessary namespaces
using namespace vanetza;
using namespace vanetza::security;

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

void CRLMessage::setSignerCertificate(const vanetza::security::Certificate& certificate)
{
    mSignerCertificate = certificate;
}

std::string CRLMessage::serializeCRL() const
{
    std::ostringstream oss;
    OutputArchive ar(oss);

    // Serialize payload
    std::string payload = serializePayload();
    ar.save_binary(payload.data(), payload.size());

    // Serialize signature
    serialize(ar, mSignature);

    return oss.str();
}

void CRLMessage::deserializeCRL(const std::string& data)
{
    std::istringstream iss(data);
    InputArchive ar(iss);

    // Deserialize payload
    std::string payload;
    ar.load_binary(reinterpret_cast<char*>(&payload), sizeof(payload));
    deserializePayload(payload);

    // Deserialize signature
    deserialize(ar, mSignature, PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
}

std::string CRLMessage::serializePayload() const
{
    std::ostringstream oss;
    OutputArchive ar(oss);

    // Serialize timestamp
    int64_t timestamp_int = mTimestamp.raw();
    ar << timestamp_int;

    // Serialize revoked certificates
    ar << mRevokedCertificates.size();
    for (const auto& hashedId : mRevokedCertificates) {
        ar.save_binary(hashedId.data(), hashedId.size());
    }

    // Serialize signer's certificate
    serialize(ar, mSignerCertificate);

    return oss.str();
}

void CRLMessage::deserializePayload(const std::string& data)
{
    std::istringstream iss(data);
    InputArchive ar(iss);

    // Deserialize timestamp
    int64_t timestamp_int;
    ar >> timestamp_int;
    mTimestamp = omnetpp::SimTime::fromRaw(timestamp_int);

    // Deserialize revoked certificates
    size_t numRevokedCertificates;
    ar >> numRevokedCertificates;
    mRevokedCertificates.resize(numRevokedCertificates);
    for (size_t i = 0; i < numRevokedCertificates; ++i) {
        ar.load_binary(mRevokedCertificates[i].data(), mRevokedCertificates[i].size());
    }

    // Deserialize signer's certificate
    deserialize(ar, mSignerCertificate);
}
