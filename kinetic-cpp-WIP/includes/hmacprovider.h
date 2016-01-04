#ifndef HMAC_PROVIDER_H_
#define HMAC_PROVIDER_H_

#include "kinetic.pb.h"

using com::seagate::kinetic::proto::Command;
using com::seagate::kinetic::proto::Message;

std::string computeHmac(const Message& message, const std::string& key);
bool validateHmac(const Message& message, const std::string& key);

#endif
