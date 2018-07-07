#pragma once
#include <mutex>
#include <sstream>

typedef void (*fnlogmsg)(const std::string& msg);
void nullhandler(const std::string& msg);

class LOG
{
  public:
    static void set_level(int level) { level_ = level; }
    static void set_handler(fnlogmsg handler) { handler_ = handler; }
    static void nullhandler(const std::string& msg){};
    LOG(int level = 0) { msg_level_ = level; }
    ~LOG();
    template <class T>
    LOG& operator<<(const T& thing)
    {
        msg_ << thing;
        return *this;
    }

  private:
    static int level_;
    static fnlogmsg handler_;
    int msg_level_ = 0;
    std::ostringstream msg_;
};
