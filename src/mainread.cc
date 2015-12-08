#include <iostream>
#include <fstream>
#include <string>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "kinetic.pb.h"
using namespace std;


// Iterates though all people in the AddressBook and prints info about them.
void checkhmac(com::seagate::kinetic::proto::Message message) {

  HMAC_CTX ctx;
  unsigned char result[20];
  unsigned int result_len = 20;
  

  HMAC_CTX_init(&ctx);

  HMAC_Init_ex(&ctx, "asdfasdf", 8, EVP_sha1(), NULL);
  HMAC_Update(&ctx,
	      reinterpret_cast<const unsigned char *>(message.
						      commandbytes().
						      c_str()),
	      message.commandbytes().length());
  cout << message.commandbytes().length() << endl;
  HMAC_Final(&ctx, result, &result_len);
  HMAC_CTX_cleanup(&ctx);

  EXPECT_EQ(message.mutable_hmacauth()->hmac()), result); 
  
}




// Main function:  Reads the entire address book from a file and prints all
//   the information inside.
int main(int argc, char* argv[]) {
  // Verify that the version of the library that we linked against is
  // compatible with the version of the headers we compiled against.
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  if (argc != 2) {
    cerr << "Usage:  " << argv[0] << " ADDRESS_BOOK_FILE" << endl;
    return -1;
  }

  com::seagate::kinetic::proto::Command command;
  com::seagate::kinetic::proto::Message message;

  {
    // Read the existing address book.
    fstream input(argv[1], ios::in | ios::binary);
    if (!message.ParseFromIstream(&input)) {
      cerr << "Failed to parse address book." << endl;
      return -1;
    }
  }

  //  checkhmac(message.mutable_hmacauth()->hmac(), message);
  command.ParseFromString(message.commandbytes());
  
  cout << "cluster version : " << command.mutable_header()->clusterversion() << endl;
  cout << "connection ID  : " << command.mutable_header()->connectionid() << endl;
  cout << "sequence : " << command.mutable_header()->sequence() << endl;
  cout << "message type : " << command.mutable_header()->messagetype() << endl;

  // Optional:  Delete all global objects allocated by libprotobuf.
  google::protobuf::ShutdownProtobufLibrary();

  return 0;
}
