#ifndef PUT_H_
#define PUT_H_

#include <nan.h>
#include "kinetic.pb.h"

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
    : Nan::AsyncWorker(callback), request(request), sequence(sequence), key(key) { };
  ~KineticPUTPDU() {};
  void Execute();
  void HandleOKCallback();
  void HandleErrorCallback();
  
};

#endif
