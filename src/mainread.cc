#include <iostream>
#include <fstream>
#include <string>
#include "kinetic.pb.h"
using namespace std;

/*
// Iterates though all people in the AddressBook and prints info about them.
void ListPeople(const com::seagate::kinetic::proto::Command command) {
    const tutorial::Person& person = address_book.person(i);

    cout << "Cluster Version : " << command.clusterversion() << endl;
    cout << "  Name: " << person.name() << endl;
    if (person.has_email()) {
      cout << "  E-mail address: " << person.email() << endl;
    }

    for (int j = 0; j < person.phone_size(); j++) {
      const tutorial::Person::PhoneNumber& phone_number = person.phone(j);

      switch (phone_number.type()) {
      case tutorial::Person::MOBILE:
        cout << "  Mobile phone #: ";
        break;
      case tutorial::Person::HOME:
        cout << "  Home phone #: ";
        break;
      case tutorial::Person::WORK:
        cout << "  Work phone #: ";
        break;
      }
      cout << phone_number.number() << endl;
    }
}
*/
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

  command.ParseFromString(message.commandbytes());
  
  cout << "cluster version : " << command.mutable_header()->clusterversion() << endl;
  cout << "connection ID  : " << command.mutable_header()->connectionid() << endl;
  cout << "sequence : " << command.mutable_header()->sequence() << endl;
  cout << "message type : " << command.mutable_header()->messagetype() << endl;

  // Optional:  Delete all global objects allocated by libprotobuf.
  google::protobuf::ShutdownProtobufLibrary();

  return 0;
}
