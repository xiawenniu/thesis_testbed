#include "database.hpp"

bool Database::query(std::string key, std::string& value)
{

    leveldb::Status queryStatus = this->levelDBObj_->Get(leveldb::ReadOptions(), key, &value);
    return queryStatus.ok();
}

bool Database::insert(std::string key, std::string value)
{
    leveldb::Status insertStatus = this->levelDBObj_->Put(leveldb::WriteOptions(), key, value);
    return insertStatus.ok();
}

bool Database::openDB(std::string dbName)
{
    leveldb::Options options;
    options.create_if_missing = true;
    leveldb::Status status = leveldb::DB::Open(options, dbName, &this->levelDBObj_);
    assert(status.ok());
    if (status.ok()) {
        return true;
    } else {
        return false;
    }
}
bool Database::delet(std::string key){

    leveldb::Status insertStatus = this->levelDBObj_->Delete(leveldb::WriteOptions(),key);
    return insertStatus.ok();
}

Database::Database(std::string dbName)
{
    this->openDB(dbName);
}

Database::~Database()
{
    delete this->levelDBObj_;
}