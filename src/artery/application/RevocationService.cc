#include "RevocationService.h"
#include "CRLMessage_m.h"

Define_Module(RevocationService);

void RevocationService::initialize()
{
    // Subscribe to CRL updates from the RevocationAuthority
    subscribe(vanetza::btp::ports::CRL);
}

void RevocationService::receive(const vanetza::btp::DataIndication& ind, omnetpp::cPacket* packet)
{
    // Check if the received packet is a CRL update
    auto crlMessage = dynamic_cast<CRLMessage*>(packet);
    if (crlMessage) {
        // Extract the revoked certificate IDs from the CRL message
        std::unordered_set<vanetza::security::CertificateId> revokedCertificates;
        for (size_t i = 0; i < crlMessage->getRevokedCertificatesArraySize(); ++i) {
            auto certificateId = vanetza::security::CertificateId::from_string(crlMessage->getRevokedCertificates(i));
            revokedCertificates.insert(certificateId);
        }
        // Update the local CRL with the received revoked certificates
        updateLocalCRL(revokedCertificates);
    }
    delete packet;
}

bool RevocationService::isRevoked(const vanetza::security::CertificateId& certificateId) const
{
    // Check if the certificate ID is present in the local CRL
    return mLocalCRL.find(certificateId) != mLocalCRL.end();
}

void RevocationService::updateLocalCRL(const std::unordered_set<vanetza::security::CertificateId>& revokedCertificates)
{
    // Update the local CRL by inserting the revoked certificates
    mLocalCRL.insert(revokedCertificates.begin(), revokedCertificates.end());
}