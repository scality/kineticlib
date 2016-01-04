#include <iostream>
#include <errno.h>
#include <string.h>
#include <nan.h>

#include "hmacprovider.h"
#include "errorProp.h"
#include "kinetic.pb.h"

using com::seagate::kinetic::proto::Command;
using com::seagate::kinetic::proto::Message;
using namespace std;

class KineticPUTPDU : public Nan::AsyncWorker {

private:
  size_t       request;
  size_t       sequence;
  std::string  key;
  std::string  output;
  char*        result;

  const char *error_prop = NULL;

public:
  KineticPUTPDU(Nan::Callback *callback,
                   size_t request,
                   size_t sequence,
                   std::string key = 0)
    : Nan::AsyncWorker(callback), request(request), sequence(sequence), key(key) { }

  ~KineticPUTPDU() {}

  /*
   * Executed inside the worker-thread. It is not safe to access V8, or V8
   * data structures here, so everything we need for input and output should
   * go on `this`.
   */
  void Execute() {
    Command command;
    Message message;

    command.mutable_header()->set_clusterversion(0);
    command.mutable_header()->set_connectionid(1234);
    command.mutable_header()->set_sequence(sequence);
    command.mutable_header()->set_messagetype(com::seagate::kinetic::proto::Command_MessageType_PUT);
    command.mutable_body()->mutable_keyvalue()->
      set_synchronization(com::seagate::kinetic::proto::Command_Synchronization_WRITETHROUGH);
    command.mutable_body()->mutable_keyvalue()->set_key(key);
    //      command.mutable_body()->mutable_keyvalue()->set_dbversion();
    //      command.mutable_body()->mutable_keyvalue()->set_newversion();

    message.set_commandbytes(command.SerializeAsString());
    message.set_authtype(com::seagate::kinetic::proto::Message_AuthType_HMACAUTH);
    message.mutable_hmacauth()->set_identity(1);

    message.mutable_hmacauth()->set_hmac(computeHmac(message, "asdfasdf"));

    message.SerializeToString(&output);

    result = new char[output.size()];
    std::copy(output.begin(), output.end(), result);

    //    google::protobuf::ShutdownProtobufLibrary();
  }

  /*
   * Executed when the async work is complete this function will be run
   * inside the main event loop so it is safe to use V8 again.
   */
  void HandleOKCallback() {
    Nan::HandleScope scope;

    v8::Local<v8::Object> buffer =
      Nan::NewBuffer(result, (uint32_t) output.size()).ToLocalChecked();
    v8::Local<v8::Value> argv[] = { Nan::Null(), buffer };
    callback->Call(2, argv);
  }

  void HandleErrorCallback() {
    Nan::HandleScope scope;

    v8::Local<v8::Value> argv[] = {
      ErrorWithProperty(error_prop, ErrorMessage()) };
    callback->Call(1, argv);
  }
};

