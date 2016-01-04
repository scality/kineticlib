#include <iostream>
#include <errno.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <nan.h>

#include "put.h"
#include "hmacprovider.h"
#include "errorProp.h"
#include "kinetic.pb.h"

using com::seagate::kinetic::proto::Command;
using com::seagate::kinetic::proto::Message;
using namespace std;

/*
 * Equivalent of:
 *
 * const err = new Error(message);
 * err[property] = true;
 */
static v8::Local<v8::Value> ErrorWithProperty(const char *property,
                                              const char *message) {
  v8::Local<v8::Value> error = Nan::Error(message);

  v8::Local<v8::String> key = Nan::New<v8::String>(property)
    .ToLocalChecked();
  error.As<v8::Object>()->Set(key, Nan::True());

  return error;
}

class KineticCreatePDU : public Nan::AsyncWorker {

private:
  size_t       request;
  size_t       sequence;
  std::string  key;
  std::string  output;
  char*        result;

  const char *error_prop = NULL;
  
public:
  KineticCreatePDU(Nan::Callback *callback,
                   size_t request,
                   size_t sequence,
                   std::string key = 0)
    : Nan::AsyncWorker(callback), request(request), sequence(sequence), key(key) { }

  ~KineticCreatePDU() {}

  /*
   * Executed inside the worker-thread. It is not safe to access V8, or V8
   * data structures here, so everything we need for input and output should
   * go on `this`.
   */
  void Execute() {
    Command command;
    Message message;

    if (request == 30){
      command.mutable_header()->set_clusterversion(0);
      command.mutable_header()->set_connectionid(1234);
      command.mutable_header()->set_sequence(sequence);
      command.mutable_header()->set_messagetype(com::seagate::kinetic::proto::Command_MessageType_NOOP);
    }
    else if (request == 4){
      command.mutable_header()->set_clusterversion(0);
      command.mutable_header()->set_connectionid(1234);
      command.mutable_header()->set_sequence(sequence);
      command.mutable_header()->set_messagetype(com::seagate::kinetic::proto::Command_MessageType_PUT);
      command.mutable_body()->mutable_keyvalue()->
        set_synchronization(com::seagate::kinetic::proto::Command_Synchronization_WRITETHROUGH);
      command.mutable_body()->mutable_keyvalue()->set_key(key);
      //      command.mutable_body()->mutable_keyvalue()->set_dbversion();
      //      command.mutable_body()->mutable_keyvalue()->set_newversion();
    }

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



class KineticParsePDU : public Nan::AsyncWorker {

private:
  std::string request;
  Command command;
  Message message;
  
  const char *error_prop = NULL;
  
public:
  KineticParsePDU(Nan::Callback *callback, std::string request)
    : Nan::AsyncWorker(callback), request(request) { }

  ~KineticParsePDU() {}

  /*
   * Executed inside the worker-thread. It is not safe to access V8, or V8
   * data structures here, so everything we need for input and output should
   * go on `this`.
   */
  void Execute() {
   
    if (!message.ParseFromString(request)){
      cout << "Failed to parse the binary string in message(message1)" << endl;
    } else {
      if (validateHmac(message, "asdfasdf")){
        if (!command.ParseFromString(message.commandbytes())){
          std::cout << "Failed to parse the binary string(command2)" << std::endl;
        }
      }
    }
    //    google::protobuf::ShutdownProtobufLibrary();
  }

  /*
   * Executed when the async work is complete this function will be run
   * inside the main event loop so it is safe to use V8 again.
   */
  void HandleOKCallback() {
    Nan::HandleScope scope;
    v8::Local<v8::Object> pduObject = Nan::New<v8::Object>();
    Nan::Set(pduObject, Nan::New("clusterVersion").ToLocalChecked(),
             Nan::New((uint32_t)command.mutable_header()->clusterversion()));
    Nan::Set(pduObject, Nan::New("ConnectionID").ToLocalChecked(),
             Nan::New((uint32_t)command.mutable_header()->connectionid()));
    if (command.mutable_header()->sequence())
      Nan::Set(pduObject, Nan::New("sequence").ToLocalChecked(),
               Nan::New((uint32_t)command.mutable_header()->sequence()));
    else 
      Nan::Set(pduObject, Nan::New("sequence").ToLocalChecked(),
               Nan::New((uint32_t)command.mutable_header()->acksequence()));     
    if (command.mutable_header()->messagetype() < 100 && command.mutable_header()->messagetype() > 1)
      Nan::Set(pduObject, Nan::New("messageType").ToLocalChecked(),
               Nan::New((uint32_t)command.mutable_header()->messagetype()));
    else
      Nan::Set(pduObject, Nan::New("messageType").ToLocalChecked(),
               Nan::New("null").ToLocalChecked());
    Nan::Set(pduObject, Nan::New("statusCode").ToLocalChecked(),
             Nan::New((uint32_t)command.mutable_status()->code()));
    v8::Local<v8::Value> argv[] = { Nan::Null(), pduObject};
    callback->Call(2, argv);
  }

  void HandleErrorCallback() {
    Nan::HandleScope scope;
    v8::Local<v8::Value> argv[] = {
      ErrorWithProperty(error_prop, ErrorMessage()) };
    callback->Call(1, argv);
  }
};

void Read(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() != 2) {
    Nan::ThrowTypeError("wrong number of arguments");
    return;
  }

  if (!info[0]->IsObject()) {
    Nan::ThrowTypeError("first argument should be a buffer");
    return;
  }

  v8::Local<v8::Object> bufferObj    = Nan::To<v8::Object>(info[0]).ToLocalChecked();
  size_t        bufferLength = node::Buffer::Length(bufferObj);
  char*         bufferData   = node::Buffer::Data(bufferObj);

  std::string data(bufferData, bufferLength);
  
  if (!info[1]->IsFunction()) {
    Nan::ThrowTypeError("second argument should be a function");
    return;
  }
  
  Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());

  Nan::AsyncQueueWorker(new KineticParsePDU(callback, data));

  return;
}

void Write(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.Length() < 3 || info.Length() > 4) {
    Nan::ThrowTypeError("wrong number of arguments");
    return;
  }

  if (!info[1]->IsNumber() || !info[0]->IsNumber()) {
    Nan::ThrowTypeError("first and second argument should be numbers");
    return;
  }
  
  size_t request = Nan::To<int>(info[0]).FromJust();
  size_t sequence = Nan::To<int>(info[1]).FromJust();

  if (request == 4){

    v8::Local<v8::Object> bufferKeyObj    = Nan::To<v8::Object>(info[2]).ToLocalChecked();
    size_t        bufferKeyLength = node::Buffer::Length(bufferKeyObj);
    char*         bufferKey   = node::Buffer::Data(bufferKeyObj);

    std::string key(bufferKey, bufferKeyLength);

    cout << key << endl;
    if (!info[3]->IsFunction()) {
      Nan::ThrowTypeError("third argument should be a function");
      return;
    }
    Nan::Callback *callback = new Nan::Callback(info[3].As<v8::Function>());
    Nan::AsyncQueueWorker(new KineticPUTPDU(callback, request, sequence, key));
    return;
  }
  
  if (!info[2]->IsFunction()) {
    Nan::ThrowTypeError("third argument should be a function");
    return;
  }
  Nan::Callback *callback = new Nan::Callback(info[2].As<v8::Function>());
  Nan::AsyncQueueWorker(new KineticCreatePDU(callback, request, sequence));
  return;
}

void Init(v8::Local<v8::Object> exports) {
  exports->Set(Nan::New("read").ToLocalChecked(),
               Nan::New<v8::FunctionTemplate>(Read)->GetFunction());
  exports->Set(Nan::New("write").ToLocalChecked(),
               Nan::New<v8::FunctionTemplate>(Write)->GetFunction());
}

NODE_MODULE(kineticcpp, Init)
