#pragma once

#include "../Models/USBDevice.h"
#include "../ThirdParty/SQLite/sqlite3.h"

#include <string>
#include <vector>

struct AllowedDevice
{
    int id;

    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;

    std::wstring deviceType;
    std::wstring description;
    std::wstring manufacturer;
};

class AllowlistManager
{
public:

    AllowlistManager();
    ~AllowlistManager();

    bool Initialize(const std::wstring& databasePath);

    bool IsAllowed(const USBDevice& device);

    bool AddDevice(const USBDevice& device);

    bool RemoveDevice(const USBDevice& device);

    std::vector<AllowedDevice> GetAllDevices();

    void Close();

private:

    sqlite3* db;

    bool CreateTables();

    std::wstring GetLastErrorMessage() const;
};