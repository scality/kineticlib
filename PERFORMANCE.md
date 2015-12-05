#Metrics kineticlib

This repository has some metrics scripts on proto/FT/PerformancesMetrics

* [KineticJS](#kineticlib) using protobufjs
  - [ServerJS](#serverjs) connect to a server that just respond
  - [Simulator](#simulator-server) connect to the simulator
* [Hackathon-node-kinetic(nan)](#hackathon-node-kinetic)
  using a Nan module and kinetic-cpp-client
* [JSON](#json) using JSON/HTTP
### How it works

* It does metrics on the client side
  - get the time between first request and last response

* It send 10 000 requests

### Kineticlib

#### ServerJS

- Clone the repository and checkout to proto proto/FT/PerformancesMetrics

```
npm install

node serverKinetic.js
```

 - On another terminal

```
node metrics.js 'path/to/file'
```

#### Simulator server

##### Pre-requires :
###### Install maven :
On Ubuntu

```
sudo apt-get install maven
```
On fedora/CentOS

```
sudo yum install maven
```

On the others patforms check https://maven.apache.org/index.html

##### How to use it :

* Clone the simulator repository at https://github.com/Kinetic/kinetic-java

```
cd kinetic-java
mvn clean package
sh bin/startSimulator.sh &> /dev/null

```

On another terminal

* Clone the repository and checkout to proto proto/FT/PerformancesMetrics

```
npm install
node metrics.js 'path/to/file'
```

### Hackathon node kinetic

For those metrics you can use the kinetic simulator

- Clone the repository https://github.com/scality/hackathon-node-kinetic

```
cd hackathon-node-kinetic.git
```

- This repository is on node 0.12, if you do not have it, use nvm
    https://github.com/creationix/nvm

```
npm run install
```

- You can change the IP of the kinetic drives at
    hackathon-node-kinetic/node_modules/kinetic-dpp/ringmodel/
    kinetic_server_config.json

- Or directly in the code in
  hackathon-node-kinetic/kinetic_cpp_linux/src/main/socket_wrapper.cc

- After that launch this script

``` js
    var Kinetic_lib = require('./index.js').ApiKinetic;
    var api = new Kinetic_lib();

    var crypto = require('crypto');
    var fs = require('fs');

    var ITERATIONS = 10000;
    var dd = crypto.randomBytes(256);
    var strEnd = '';
    var time1 = [];
    var counter = 1;

    if (process.argv[2] === undefined){
        process.stdout.write(
            "Usage: node metrics.js 'path/to/file'\n");
        process.exit();
    }

    var time0 = process.hrtime();
    for (var i = 1; i <= ITERATIONS; i++){
        api.put_bl(dd, function parse(err, data) {
            if (err)
                console.log(err);
            else {
                counter++;
                time1 = process.hrtime(time0);
                strEnd += '[ ' + time1[0] +  ' , ' + time1[1] + ' ]\n';
                if (counter === ITERATIONS)
                    fs.writeFileSync(process.argv[2], strEnd);
            }
        });
    }
```

This script have to be launch like this

``` js
node metrics.js 'path/to/file' &> /dev/null
```

### JSON

- Clone the repository and checkout to proto proto/FT/PerformancesMetrics

```
npm install
node metrics/JSON/serverMetrics.js
```

 - On another terminal

```
node metrics/JSON/metrics.js 'path/to/file'
```

### Result on fedora laptop

|      Language used      | type of request |  time (µs) |   Server  |
|:-----------------------:|-----------------|:----------:|:---------:|
|            JS           |     protobuf    | 6 377 560  | script js |
|            JS           |     protobuf    | 21 882 943 | Simulator |
|            JS           |       JSON      | 13 674 900 | script js |
| C++ and JS (Nan module) |     protobuf    | 37 929 551 | Simulator |
