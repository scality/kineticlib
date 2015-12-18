const kinetic = require('./index');
const crypto = require("crypto");
try {
    kinetic.write(30, 1, function(err, data){
        if (err)
            console.log(err);
        console.log("length of JS DATA : ", data.length);
        kinetic.read(data, function(err, pb){
            if (err)
                console.log(err)
            console.log(pb);
        })
    });
} catch (err) {
    console.log(err);
}
