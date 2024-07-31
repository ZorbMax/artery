// ActiveRevocationMetrics.h
#pragma once

#include <string>
#include <vector>

class ActiveRevocationMetrics
{
public:
    void recordCRLSize(size_t size, double simulationTime);
    void recordCRLDistribution(size_t messageSize, double simulationTime);
    void recordV2VProcessingTime(double processingTime, double simulationTime);

    double calculateAverageCRLSize() const;
    size_t getMaxCRLSize() const;
    double calculateTotalCRLOverhead() const;
    double calculateAverageCRLMessageSize() const;
    // void recordMessageDiscard(const std::string& hashedId, const std::string& discardingVehicleId, double timestamp);

    void printMetrics() const;
    void exportToCSV(const std::string& filename) const;

private:
    struct CRLEntry {
        size_t size;
        double time;
    };

    struct CRLDistributionMessage {
        size_t size;
        double time;
    };

    struct V2VProcessingEntry {
        double processingTime;
        double simulationTime;
    };

    std::vector<V2VProcessingEntry> v2vProcessingTimes;
    std::vector<CRLEntry> crlEntries;
    std::vector<CRLDistributionMessage> crlDistributions;
    double calculateAverageV2VProcessingTime() const;
    // std::map<std::string, double> mRevocationStartTimes;
    // std::map<std::string, std::map<std::string, double>> mFirstDiscardTimes;
};