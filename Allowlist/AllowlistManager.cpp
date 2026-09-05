#include "AllowlistManager.h"
#include "../Classifier/DeviceClassifier.h"

#include <windows.h>
#include <iostream>


AllowlistManager::AllowlistManager()
    : db(nullptr)
{
}


AllowlistManager::~AllowlistManager()
{
    Close();
}


bool AllowlistManager::Initialize(const std::wstring& databasePath)
{
    if (db != nullptr)
    {
        return true;
    }

    int result =
        sqlite3_open16(
            databasePath.c_str(),
            &db
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Could not open SQLite database.\n";

        if (db != nullptr)
        {
            std::wcerr
                << L"SQLite Error: "
                << GetLastErrorMessage()
                << L"\n";
        }

        return false;
    }

    std::wcout
        << L"[OK] SQLite database opened.\n";

    if (!CreateTables())
    {
        std::wcerr
            << L"[ERROR] Could not create database tables.\n";

        return false;
    }

    return true;
}


bool AllowlistManager::CreateTables()
{
    const char* sql = R"SQL(

        CREATE TABLE IF NOT EXISTS allowed_devices
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            vendor_id TEXT NOT NULL,
            product_id TEXT NOT NULL,
            serial_number TEXT NOT NULL,

            device_type TEXT,
            description TEXT,
            manufacturer TEXT,

            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(vendor_id, product_id, serial_number)
        );

    )SQL";

    char* errorMessage = nullptr;

    int result =
        sqlite3_exec(
            db,
            sql,
            nullptr,
            nullptr,
            &errorMessage
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Failed to create table.\n";

        if (errorMessage != nullptr)
        {
            std::cerr
                << "SQLite Error: "
                << errorMessage
                << "\n";

            sqlite3_free(errorMessage);
        }

        return false;
    }

    std::wcout
        << L"[OK] Allowlist table ready.\n";

    return true;
}


bool AllowlistManager::IsAllowed(
    const USBDevice& device)
{
    if (db == nullptr)
    {
        return false;
    }

    const wchar_t* sql =
        L"SELECT COUNT(*) "
        L"FROM allowed_devices "
        L"WHERE vendor_id = ? "
        L"AND product_id = ? "
        L"AND serial_number = ?;";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Failed to prepare allowlist query.\n";

        return false;
    }

    sqlite3_bind_text16(
        statement,
        1,
        device.vendorId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        2,
        device.productId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        3,
        device.serialNumber.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    bool allowed = false;

    result = sqlite3_step(statement);

    if (result == SQLITE_ROW)
    {
        int count =
            sqlite3_column_int(statement, 0);

        allowed = (count > 0);
    }

    sqlite3_finalize(statement);

    return allowed;
}


bool AllowlistManager::AddDevice(
    const USBDevice& device)
{
    if (db == nullptr)
    {
        return false;
    }

    const wchar_t* sql =
        L"INSERT OR IGNORE INTO allowed_devices "
        L"(vendor_id, product_id, serial_number, "
        L"device_type, description, manufacturer) "
        L"VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        std::wcerr
            << L"[ERROR] Failed to prepare INSERT statement.\n";

        return false;
    }

    std::wstring deviceType =
        DeviceClassifier::ToString(device.type);

    sqlite3_bind_text16(
        statement,
        1,
        device.vendorId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        2,
        device.productId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        3,
        device.serialNumber.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        4,
        deviceType.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        5,
        device.description.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        6,
        device.manufacturer.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    result = sqlite3_step(statement);

    bool success =
        (result == SQLITE_DONE);

    sqlite3_finalize(statement);

    if (success)
    {
        std::wcout
            << L"[OK] Device added to allowlist.\n";
    }
    else
    {
        std::wcerr
            << L"[ERROR] Failed to add device to allowlist.\n";
    }

    return success;
}


bool AllowlistManager::RemoveDevice(
    const USBDevice& device)
{
    if (db == nullptr)
    {
        return false;
    }

    const wchar_t* sql =
        L"DELETE FROM allowed_devices "
        L"WHERE vendor_id = ? "
        L"AND product_id = ? "
        L"AND serial_number = ?;";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        return false;
    }

    sqlite3_bind_text16(
        statement,
        1,
        device.vendorId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        2,
        device.productId.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    sqlite3_bind_text16(
        statement,
        3,
        device.serialNumber.c_str(),
        -1,
        SQLITE_TRANSIENT
    );

    result = sqlite3_step(statement);

    bool success =
        (result == SQLITE_DONE);

    sqlite3_finalize(statement);

    if (success)
    {
        std::wcout
            << L"[OK] Device removed from allowlist.\n";
    }

    return success;
}


std::vector<AllowedDevice>
AllowlistManager::GetAllDevices()
{
    std::vector<AllowedDevice> devices;

    if (db == nullptr)
    {
        return devices;
    }

    const wchar_t* sql =
        L"SELECT id, vendor_id, product_id, "
        L"serial_number, device_type, "
        L"description, manufacturer "
        L"FROM allowed_devices "
        L"ORDER BY id;";

    sqlite3_stmt* statement = nullptr;

    int result =
        sqlite3_prepare16_v2(
            db,
            sql,
            -1,
            &statement,
            nullptr
        );

    if (result != SQLITE_OK)
    {
        return devices;
    }

    while (sqlite3_step(statement) == SQLITE_ROW)
    {
        AllowedDevice device;

        device.id =
            sqlite3_column_int(statement, 0);

        const void* vendor =
            sqlite3_column_text16(statement, 1);

        const void* product =
            sqlite3_column_text16(statement, 2);

        const void* serial =
            sqlite3_column_text16(statement, 3);

        const void* type =
            sqlite3_column_text16(statement, 4);

        const void* description =
            sqlite3_column_text16(statement, 5);

        const void* manufacturer =
            sqlite3_column_text16(statement, 6);

        if (vendor)
            device.vendorId =
                static_cast<const wchar_t*>(vendor);

        if (product)
            device.productId =
                static_cast<const wchar_t*>(product);

        if (serial)
            device.serialNumber =
                static_cast<const wchar_t*>(serial);

        if (type)
            device.deviceType =
                static_cast<const wchar_t*>(type);

        if (description)
            device.description =
                static_cast<const wchar_t*>(description);

        if (manufacturer)
            device.manufacturer =
                static_cast<const wchar_t*>(manufacturer);

        devices.push_back(device);
    }

    sqlite3_finalize(statement);

    return devices;
}


std::wstring
AllowlistManager::GetLastErrorMessage() const
{
    if (db == nullptr)
    {
        return L"Unknown SQLite error";
    }

    const char* error =
        sqlite3_errmsg(db);

    if (error == nullptr)
    {
        return L"Unknown SQLite error";
    }

    int requiredSize =
        MultiByteToWideChar(
            CP_UTF8,
            0,
            error,
            -1,
            nullptr,
            0
        );

    if (requiredSize <= 0)
    {
        return L"SQLite error";
    }

    std::wstring result(requiredSize, L'\0');

    MultiByteToWideChar(
        CP_UTF8,
        0,
        error,
        -1,
        &result[0],
        requiredSize
    );

    if (!result.empty() &&
        result.back() == L'\0')
    {
        result.pop_back();
    }

    return result;
}


void AllowlistManager::Close()
{
    if (db != nullptr)
    {
        sqlite3_close(db);
        db = nullptr;
    }
}