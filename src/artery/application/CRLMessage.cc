#include "CRLMessage.h"
#include <vanetza/security/signature.hpp>

CRLMessage::CRLMessage(const char* name, short kind) : omnetpp::cPacket(name, kind) {}

void CRLMessage::parsimPack(omnetpp::cCommBuffer* buffer) const {
    omnetpp::cPacket::parsimPack(buffer);
    buffer->pack(mTimestamp);
    buffer->pack(mRevokedCertificates.size());
    for (const auto& hashedId : mRevokedCertificates) {
        buffer->pack(hashedId.data(), hashedId.size());
    }
    buffer->pack(mSignature.data(), mSignature.size());
    // Assuming mSignerCertificate has a method to serialize itself
    buffer->pack(mSignerCertificate);
}

void CRLMessage::parsimUnpack(omnetpp::cCommBuffer* buffer) {
    omnetpp::cPacket::parsimUnpack(buffer);
    buffer->unpack(mTimestamp);
    size_t numRevokedCertificates;
    buffer->unpack(numRevokedCertificates);
    mRevokedCertificates.clear();
    for (size_t i = 0; i < numRevokedCertificates; ++i) {
        vanetza::security::HashedId8 hashedId;
        buffer->unpack(hashedId.data(), hashedId.size());
        mRevokedCertificates.push_back(hashedId);
    }
    buffer->unpack(mSignature.data(), mSignature.size());
    // Assuming mSignerCertificate has a method to deserialize itself
    buffer->unpack(mSignerCertificate);
}

// Getters
omnetpp::simtime_t CRLMessage::getTimestamp() const { return mTimestamp; }
const std::vector<vanetza::security::HashedId8>& CRLMessage::getRevokedCertificates() const { return mRevokedCertificates; }
const vanetza::security::EcdsaSignature& CRLMessage::getSignature() const { return mSignature; }
const vanetza::security::Certificate& CRLMessage::getSignerCertificate() const { return mSignerCertificate; }

// Setters
void CRLMessage::setRevokedCertificates(const std::vector<vanetza::security::HashedId8>& revokedCertificates) { mRevokedCertificates = revokedCertificates; }
void CRLMessage::setSignature(const vanetza::security::EcdsaSignature& signature) { mSignature = signature; }
void CRLMessage::setSignerCertificate(const vanetza::security::Certificate& certificate) { mSignerCertificate = certificate; }

// ASN.1 encoding methods
std::string CRLMessage::encode() const {
    std::ostringstream oss;
    oss << mTimestamp;
    for (const auto& hashedId : mRevokedCertificates) {
        oss.write(reinterpret_cast<const char*>(hashedId.data()), hashedId.size());
    }
    return oss.str();
}

std::size_t CRLMessage::size() const {
    return encode().size();
}
