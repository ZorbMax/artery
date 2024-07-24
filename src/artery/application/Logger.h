#ifndef LOGGER_H
#define LOGGER_H

#include <fstream>
#include <mutex>
#include <string>

class Logger
{
private:
    static std::ofstream logFile;
    static std::mutex logMutex;

public:
    static void init(const std::string& filename);
    static void log(const std::string& message);
    static void close();
};

#endif  // LOGGER_H