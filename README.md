Client Certificate Demo

server's private key is `server.key`, 
our server certificate (`server.pem`). 

`alice.pfx` which was issued by us (the issuer is Demo CA)
`bob.pfx`, which is a self-signed certificate (the issuer is Bob himself)

import both client certificates
Leave the passphrase empty.

Start the server with `npm install && npm start`, 
open https://localhost:9999

$ curl --insecure --cert alice.pfx --cert-type p12 https://localhost:9999/authenticate
Hello Alice, your certificate was issued by Demo CA!

$ curl --insecure --cert bob.pfx --cert-type p12 https://localhost:9999/authenticate
Sorry Bob, certificates from Bob are not welcome here.
