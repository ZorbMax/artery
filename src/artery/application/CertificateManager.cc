#include "CertificateManager.h"

#include <algorithm>

CertificateManager::CertificateManager()
{
    // Constructor
}

bool CertificateManager::verifyCertificate(const vanetza::security::Certificate& certificate)
{
    // Implement certificate validation logic here
    // For now, we assume all certificates are valid
    return true;
}

bool CertificateManager::isRevoked(const vanetza::security::HashedId8& certificateHash)
{
    return std::find(mLocalCRL.begin(), mLocalCRL.end(), certificateHash) != mLocalCRL.end();
}

void CertificateManager::updateLocalCRL(const std::vector<vanetza::security::HashedId8>& revokedCertificates)
{
    mLocalCRL.insert(mLocalCRL.end(), revokedCertificates.begin(), revokedCertificates.end());
    std::sort(mLocalCRL.begin(), mLocalCRL.end());
    mLocalCRL.erase(std::unique(mLocalCRL.begin(), mLocalCRL.end()), mLocalCRL.end());
}
