{
    "targets": [
        {
            "target_name": "kinetic-cpp",
            "sources": [ "src/cpp/kinetic-cpp.cpp",
                         "src/cpp/kinetic.pb.cc"
                       ],
            "cflags": ["-std=c++11"],
            "cflags_cc!": [ "-fno-rtti" ],
            "include_dirs" : [
                "<!(node -e \"require('nan')\")",
                "src/cpp"
            ],
            "libraries": [
                         "-lprotobuf",
                         "-lssl",
                         "-lcrypto",
            ]
        }
    ]
}
