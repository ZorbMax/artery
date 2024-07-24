#include "Logger.h"

std::ofstream Logger::logFile;
std::mutex Logger::logMutex;

void Logger::init(const std::string& filename)
{
    logFile.open(filename, std::ios::app);
}

void Logger::log(const std::string& message)
{
    std::lock_guard<std::mutex> lock(logMutex);
    logFile << message << std::endl;
    logFile.flush();
}

void Logger::close()
{
    logFile.close();
}