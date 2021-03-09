const http = require('http');
const fs = require('fs');
const port = 1337;

const app = http.createServer((req,res) => {
    var ip = (req.headers['x-forwarded-for'] || '').split(',').pop() || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress || 
         req.connection.socket.remoteAddress;
    var code = 200;     
    try {
        res.end(fs.readFileSync(__dirname + req.url.split("?")[0]));
    } catch(e) { code = 404; }
    res.writeHead(code);
    console.log(ip+" \""+req.method+" "+req.url+" HTTP/"+req.httpVersion+"\" "+code);
});

app.listen(port);
console.log('Serving HTTP at http://localhost:'+port+" ...");
