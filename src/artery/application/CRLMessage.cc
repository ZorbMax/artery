// CRLMessage.cc
#include "CRLMessage.h"
#include <vanetza/security/signature.hpp>

CRLMessage::CRLMessage(const char* name, short kind) : omnetpp::cPacket(name, kind)
{
}

/**
 * @brief Serializes the CRLMessage object into a buffer for network transmission.
 *
 * This method packs the fields of the CRLMessage object into the provided buffer
 * in a specific order. It first calls the parsimPack method of the base class
 * (omnetpp::cPacket) to pack any inherited fields. Then, it packs the mTimestamp
 * field, followed by the size of the mRevokedCertificates vector. Finally, it
 * iterates over each HashedId8 object in the mRevokedCertificates vector and packs
 * the raw bytes of each object into the buffer.
 *
 * @param buffer The buffer to pack the object into.
 */
void CRLMessage::parsimPack(omnetpp::cCommBuffer* buffer) const {
    omnetpp::cPacket::parsimPack(buffer);
    buffer->pack(mTimestamp);
    buffer->pack(mRevokedCertificates.size());
    for (const auto& hashedId : mRevokedCertificates) {
        buffer->pack(hashedId.data(), hashedId.size());
    }

    // TODO: pack the signature and the certificate

}

/**
 * @brief Deserializes the CRLMessage object from a buffer received over the network.
 *
 * This method unpacks the fields of the CRLMessage object from the provided buffer
 * in the same order as they were packed by the parsimPack method. It first calls
 * the parsimUnpack method of the base class (omnetpp::cPacket) to unpack any
 * inherited fields. Then, it unpacks the mTimestamp field, followed by the number
 * of revoked certificates. It clears the mRevokedCertificates vector and iterates
 * the specified number of times, unpacking the raw bytes of each HashedId8 object
 * from the buffer and adding them to the mRevokedCertificates vector.
 *
 * @param buffer The buffer to unpack the object from.
 */
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

    // TODO: unpack the signature and the certificate

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

const vanetza::security::Certificate& CRLMessage::getSignerCertificate() const {
    return mSignerCertificate;
}


void CRLMessage::setRevokedCertificates(const std::vector<vanetza::security::HashedId8>& revokedCertificates)
{
    mRevokedCertificates = revokedCertificates;
}

void CRLMessage::setSignature(const vanetza::security::EcdsaSignature& signature)
{
    mSignature = signature;
}

void CRLMessage::setSignerCertificate(const vanetza::security::Certificate& certificate) {
    mSignerCertificate = certificate;
}