#include <iostream>
#include <fstream>
#include <string>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "kinetic.pb.h"
using namespace std;

// This function fills in a Person message based on user input.
void PromptForAddress(com::seagate::kinetic::proto::Command_Header* command) {

  }

// This function fills in a Person message based on user input.
void setMessage(com::seagate::kinetic::proto::Message* message) {

}

// Main function:  Reads the entire address book from a file,
//   adds one command based on user input, then writes it back out to the same
//   file.
int main(int argc, char* argv[]) {
  // Verify that the version of the library that we linked against is
  // compatible with the version of the headers we compiled against.
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  if (argc != 2) {
    cerr << "Usage:  " << argv[0] << " REQUEST_FILE" << endl;
    return -1;
  }

  com::seagate::kinetic::proto::Command command;
  com::seagate::kinetic::proto::Message message;

  int clusterVersion = 0;
  int connectionId = 1234;
  int sequence = 1;

  command.mutable_header()->set_clusterversion(clusterVersion);
  command.mutable_header()->set_connectionid(connectionId);
  command.mutable_header()->set_sequence(sequence);
  command.mutable_header()->set_messagetype(com::seagate::kinetic::proto::Command_MessageType_NOOP);
  
  message.set_commandbytes(command.SerializeAsString());
  message.set_authtype(com::seagate::kinetic::proto::Message_AuthType_HMACAUTH);
  message.mutable_hmacauth()->set_identity(1);

  unsigned char result[20];
  unsigned int result_len = 20;
  uint32_t message_length_bigendian = message.commandbytes().length();
  


  // Initialize HMAC object.
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  // Set HMAC key.
  HMAC_Init_ex(&ctx, "asdfasdf", 8, EVP_sha1(), NULL);
  HMAC_Update(&ctx, reinterpret_cast<const unsigned char *>(message.commandbytes().c_str()),
              message.commandbytes().length());
  cout << message.commandbytes().length() << endl;
  cout << "qweqweqe" << endl;
  HMAC_Final(&ctx, result, &result_len);
  cout << "qweqweq2e" << endl;
  HMAC_CTX_cleanup(&ctx);
  
  message.mutable_hmacauth()->set_hmac(result);
  
  {
    // Read the existing address book.
    fstream input(argv[1], ios::in | ios::binary);
    if (!input) {
      cout << argv[1] << ": File not found.  Creating a new file." << endl;
    } else if (!message.ParseFromIstream(&input)) {
      cerr << "Failed to parse address book." << endl;
      return -1;
    }
  }
  
  // Add an address.
  {
    // Write the new address book back to disk.
    fstream output(argv[1], ios::out | ios::trunc | ios::binary);
    if (!message.SerializeToOstream(&output)) {
      cerr << "Failed to write address book." << endl;
      return -1;
    }
  }

  // Optional:  Delete all global objects allocated by libprotobuf.
  google::protobuf::ShutdownProtobufLibrary();

  return 0;
}
