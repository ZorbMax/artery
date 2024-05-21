#include "CRLMessage.h"

#include <vanetza/common/archives.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/signature.hpp>

#include <cstring>

// Include necessary namespaces
using namespace vanetza;
using namespace vanetza::security;

CRLMessage::CRLMessage(const char* name, short kind) : omnetpp::cPacket(name, kind)
{
}

void CRLMessage::parsimPack(omnetpp::cCommBuffer* buffer) const
{
    omnetpp::cPacket::parsimPack(buffer);
    buffer->pack(mTimestamp.dbl());  // Convert SimTime to double for packing
    buffer->pack(mRevokedCertificates.size());
    for (const auto& hashedId : mRevokedCertificates) {
        buffer->pack(hashedId.data(), hashedId.size());
    }

    // Serialize Signature
    std::basic_stringbuf<char> sigBufStream;
    vanetza::OutputArchive sigArchive(sigBufStream);
    vanetza::security::serialize(sigArchive, mSignature);
    auto sigBufferStr = sigBufStream.str();
    buffer->pack(sigBufferStr.size());
    buffer->pack(sigBufferStr.data(), sigBufferStr.size());

    // Serialize Certificate
    std::basic_stringbuf<char> certBufStream;
    vanetza::OutputArchive certArchive(certBufStream);
    vanetza::security::serialize(certArchive, mSignerCertificate);
    auto certBufferStr = certBufStream.str();
    buffer->pack(certBufferStr.size());
    buffer->pack(certBufferStr.data(), certBufferStr.size());
}

void CRLMessage::parsimUnpack(omnetpp::cCommBuffer* buffer)
{
    omnetpp::cPacket::parsimUnpack(buffer);
    double timestamp;
    buffer->unpack(timestamp);  // Unpack as double and convert to SimTime
    mTimestamp = omnetpp::SimTime(timestamp);
    size_t numRevokedCertificates;
    buffer->unpack(numRevokedCertificates);
    mRevokedCertificates.clear();
    for (size_t i = 0; i < numRevokedCertificates; ++i) {
        vanetza::security::HashedId8 hashedId;
        buffer->unpack(hashedId.data(), hashedId.size());
        mRevokedCertificates.push_back(hashedId);
    }

    // Deserialize Signature
    size_t sigSize;
    buffer->unpack(sigSize);
    std::vector<char> sigBuffer(sigSize);
    buffer->unpack(sigBuffer.data(), sigSize);
    std::basic_stringbuf<char> sigBufStream(std::string(sigBuffer.begin(), sigBuffer.end()));
    vanetza::InputArchive sigArchive(sigBufStream);
    vanetza::security::PublicKeyAlgorithm algorithm = vanetza::security::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
    vanetza::security::deserialize(sigArchive, mSignature, algorithm);

    // Deserialize Certificate
    size_t certSize;
    buffer->unpack(certSize);
    std::vector<char> certBuffer(certSize);
    buffer->unpack(certBuffer.data(), certSize);
    std::basic_stringbuf<char> certBufStream(std::string(certBuffer.begin(), certBuffer.end()));
    vanetza::InputArchive certArchive(certBufStream);
    vanetza::security::deserialize(certArchive, mSignerCertificate);
}

void serialize(vanetza::OutputArchive& ar, const CRLMessage& crlMessage)
{
    // Serialize the timestamp
    int64_t timestamp_int = crlMessage.getTimestamp().raw();
    ar << timestamp_int;

    // Serialize the signer's certificate
    serialize(ar, crlMessage.getSignerCertificate());

    // Serialize the list of revoked certificates
    ar << crlMessage.getRevokedCertificates().size();
    for (const auto& hashedId : crlMessage.getRevokedCertificates()) {
        ar.save_binary(hashedId.data(), hashedId.size());
    }
}

void deserialize(vanetza::InputArchive& ar, CRLMessage& crlMessage)
{
    int64_t timestamp_int;
    ar >> timestamp_int;
    crlMessage.setTimestamp(omnetpp::SimTime::fromRaw(timestamp_int));

    size_t numRevokedCertificates;
    ar >> numRevokedCertificates;
    std::vector<vanetza::security::HashedId8> revokedCertificates(numRevokedCertificates);
    for (size_t i = 0; i < numRevokedCertificates; ++i) {
        vanetza::security::HashedId8 hashedId;
        ar.load_binary(hashedId.data(), hashedId.size());
        revokedCertificates[i] = hashedId;
    }
    crlMessage.setRevokedCertificates(revokedCertificates);

    vanetza::security::EcdsaSignature signature;
    PublicKeyAlgorithm algorithm = PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256;
    deserialize(ar, signature, algorithm);
    crlMessage.setSignature(signature);

    vanetza::security::Certificate certificate;
    deserialize(ar, certificate);
    crlMessage.setSignerCertificate(certificate);
}

// Getters
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

// Setters
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
