#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

class PassiveRevocationMetrics
{
public:
    void recordPseudonymMessage(size_t messageSize, double simulationTime)
    {
        pseudonymMessages.push_back({messageSize, simulationTime});
    }

    void recordEnrollmentRequest(size_t messageSize, double simulationTime)
    {
        enrollmentRequests.push_back({messageSize, simulationTime});
    }

    void recordRevocationStart(const std::string& vehicleId, double simulationTime)
    {
        revocationEvents[vehicleId] = {simulationTime, 0.0};
    }

    void recordLastValidMessage(const std::string& vehicleId, double simulationTime)
    {
        if (revocationEvents.find(vehicleId) != revocationEvents.end()) {
            revocationEvents[vehicleId].lastValidMessageTime = simulationTime;
        }
    }

    void printMetrics() const
    {
        double totalOverhead = calculateTotalNetworkOverhead();

        std::cout << "Total Network Overhead: " << totalOverhead << " bytes\n";
    }

    void exportToCSV(const std::string& filename) const
    {
        std::ofstream file(filename);
        file << "Simulation Time,Event Type,Vehicle ID,Message Size\n";

        for (const auto& msg : pseudonymMessages) {
            file << msg.second << ",PseudonymMessage,," << msg.first << "\n";
        }

        for (const auto& msg : enrollmentRequests) {
            file << msg.second << ",EnrollmentRequest,," << msg.first << "\n";
        }

        for (const auto& event : revocationEvents) {
            file << event.second.revocationStartTime << ",RevocationStart," << event.first << ",\n";
            if (event.second.lastValidMessageTime > 0) {
                file << event.second.lastValidMessageTime << ",LastValidMessage," << event.first << ",\n";
            }
        }
    }

private:
    struct RevocationEvent {
        double revocationStartTime;
        double lastValidMessageTime;
    };

    std::vector<std::pair<size_t, double>> pseudonymMessages;  // <message size, time>
    std::vector<std::pair<size_t, double>> enrollmentRequests;  // <message size, time>
    std::map<std::string, RevocationEvent> revocationEvents;  // <vehicleId, RevocationEvent>

    double calculateTotalNetworkOverhead() const
    {
        double total = 0.0;
        for (const auto& msg : pseudonymMessages) {
            total += msg.first;
        }
        for (const auto& msg : enrollmentRequests) {
            total += msg.first;
        }
        return total;
    }
};