// CRLMessage.cc
#include "CRLMessage.h"
#include <vanetza/security/signature.hpp>

CRLMessage::CRLMessage(const char* name, short kind) : omnetpp::cPacket(name, kind)
{
}

CRLMessage* CRLMessage::dup() const
{
    return new CRLMessage(*this);
}

void CRLMessage::parsimPack(omnetpp::cCommBuffer* buffer) const
{
    omnetpp::cPacket::parsimPack(buffer);
    buffer->pack(mTimestamp);
    buffer->pack(mRevokedCertificates.size());
    for (const auto& hashedId : mRevokedCertificates) {
        buffer->pack(hashedId.data(), hashedId.size());
    }
}

void CRLMessage::parsimUnpack(omnetpp::cCommBuffer* buffer)
{
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
}

omnetpp::simtime_t CRLMessage::getTimestamp() const
{
    return mTimestamp;
}

std::vector<vanetza::security::HashedId8>& CRLMessage::getRevokedCertificates()
{
    return mRevokedCertificates;
}

void CRLMessage::setSignature(const vanetza::security::EcdsaSignature& signature)
{
    mSignature = signature;
}
