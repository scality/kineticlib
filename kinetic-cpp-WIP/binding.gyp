{
    "targets": [
        {
            "target_name": "kinetic-cpp",
            "sources": [
                                "src/cpp/kinetic.pb.cc",
                                "src/cpp/kinetic-cpp.cpp",
                                "src/cpp/put.cpp",
                                "src/cpp/hmacprovider.cpp",
                                "src/cpp/errorProp.cpp"
                       ],
            "cflags": ["-std=c++11"],
            "cflags_cc!": [ "-fno-rtti" ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")",
                "./includes"
            ],
            "libraries": [
                         "-lprotobuf",
                         "-lssl",
                         "-lcrypto",
            ]
        }
    ]
}
