#include <iostream>
#include <errno.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "kinetic.pb.h"
#include "put.h"

#include <nan.h>

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

