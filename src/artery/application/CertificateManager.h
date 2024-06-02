#ifndef CERTIFICATE_MANAGER_H
#define CERTIFICATE_MANAGER_H

#include "vanetza/security/certificate.hpp"
#include "vanetza/security/ecdsa256.hpp"

#include <vector>

class CertificateManager
{
public:
    CertificateManager();
    bool verifyCertificate(const vanetza::security::Certificate& certificate);
    bool isRevoked(const vanetza::security::HashedId8& certificateHash);
    void updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates);

private:
    std::vector<vanetza::security::HashedId8> mLocalCRL;
};

#endif  // CERTIFICATE_MANAGER_H
