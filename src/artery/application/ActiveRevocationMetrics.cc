// ActiveRevocationMetrics.cpp
#include "ActiveRevocationMetrics.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <numeric>

void ActiveRevocationMetrics::recordCRLSize(size_t size, double simulationTime)
{
    crlEntries.push_back({size, simulationTime});
}

void ActiveRevocationMetrics::recordCRLDistribution(size_t messageSize, double simulationTime)
{
    crlDistributions.push_back({messageSize, simulationTime});
}

double ActiveRevocationMetrics::calculateAverageCRLSize() const
{
    if (crlEntries.empty())
        return 0.0;

    double sum = std::accumulate(crlEntries.begin(), crlEntries.end(), 0.0, [](double acc, const CRLEntry& entry) { return acc + entry.size; });

    return sum / crlEntries.size();
}

size_t ActiveRevocationMetrics::getMaxCRLSize() const
{
    if (crlEntries.empty())
        return 0;

    return std::max_element(crlEntries.begin(), crlEntries.end(), [](const CRLEntry& a, const CRLEntry& b) { return a.size < b.size; })->size;
}

double ActiveRevocationMetrics::calculateTotalCRLOverhead() const
{
    return std::accumulate(crlDistributions.begin(), crlDistributions.end(), 0.0, [](double sum, const CRLDistributionMessage& msg) { return sum + msg.size; });
}

double ActiveRevocationMetrics::calculateAverageCRLMessageSize() const
{
    if (crlDistributions.empty())
        return 0.0;

    double sum =
        std::accumulate(crlDistributions.begin(), crlDistributions.end(), 0.0, [](double acc, const CRLDistributionMessage& msg) { return acc + msg.size; });

    return sum / crlDistributions.size();
}

void ActiveRevocationMetrics::printMetrics() const
{
    std::cout << "=== Active Revocation Metrics ===\n";
    std::cout << "Average CRL Size: " << calculateAverageCRLSize() << " entries\n";
    std::cout << "Maximum CRL Size: " << getMaxCRLSize() << " entries\n";
    std::cout << "Total CRL Distribution Overhead: " << calculateTotalCRLOverhead() << " bytes\n";
    std::cout << "Average CRL Message Size: " << calculateAverageCRLMessageSize() << " bytes\n";
    std::cout << "================================\n";
}

void ActiveRevocationMetrics::exportToCSV(const std::string& filename) const
{
    std::ofstream file(filename);
    file << "Simulation Time,CRL Size,CRL Message Size\n";

    size_t crlIndex = 0;
    size_t distributionIndex = 0;

    while (crlIndex < crlEntries.size() || distributionIndex < crlDistributions.size()) {
        if (crlIndex < crlEntries.size() &&
            (distributionIndex >= crlDistributions.size() || crlEntries[crlIndex].time <= crlDistributions[distributionIndex].time)) {
            file << crlEntries[crlIndex].time << "," << crlEntries[crlIndex].size << ",\n";
            crlIndex++;
        } else {
            file << crlDistributions[distributionIndex].time << ",," << crlDistributions[distributionIndex].size << "\n";
            distributionIndex++;
        }
    }
}

// void ActiveRevocationMetrics::recordMessageDiscard(const std::string& hashedId, const std::string& discardingVehicleId, double timestamp)
// {
//     if (mRevocationStartTimes.count(hashedId) > 0) {
//         if (mFirstDiscardTimes[hashedId].count(discardingVehicleId) == 0) {
//             mFirstDiscardTimes[hashedId][discardingVehicleId] = timestamp;
//         }
//     }
// }