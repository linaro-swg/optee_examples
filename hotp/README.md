# HMAC based One Time Password in OP-TEE
[HMAC] based One Time Passwords or shortly just 'HOTP' has been around for many
years and was initially defined in [RFC4226] back in 2005. Since then it has
been a popular choice for doing [two factor authentication]. With the
implementation here we are showing how one could leverage OP-TEE for generating
such HMAC based One Time Passwords in a secure manner.

## Client (OP-TEE) / Server solution
The most common way of using HOTP is in a client/server setup, where the client
needs to authenticate itself to be able to get access to some resources on the
server. In those cases the server will ask for an One Time Password, the client
will generate that and send it over to the server and if the server is OK with
the password it will grant access to the client.

Technically how it is working is that the server and the client needs to agree
on shared key ('`K`') and also start from the same counter ('`C`'). How that is
done in practice is another topic, but RFC4226 has some discussion about it. You
should at least have a secure channel between the client and the server when
sharing the key, but even better would be if you could establish a secure
channel all the way down to the TEE (currently we have TCP/UDP support in
OP-TEE, but not TLS).

When both the server and the client knows about and use the same key and
counter they can start doing client authentication using HOTP. In short what
happens is that both the client and the server computes the same HOTP and the
server compares the result of both computations (which should be the same to
grant access). How that could work can be seen in the sequence diagram below.

In the current implementation we have OP-TEE acting as a client and the server
is a remote service running somewhere else. There is no server implemented, but
that should be pretty easy to add in a real scenario. The important thing here
is to be able to register the shared key in the TEE and to get HOTP values from
the TEE on request.

Since the current implementation works as a client we do not need to think about
implementing the look-ahead synchronization window ('`s`') nor do we have to
think about adding throttling (which prevents/slows down brute force attacks).

#### Sequence diagram - Client / Server
![Client Server based HOTP using OP-TEE](img/sequence_diagram_01.png?raw=true "Client Server based HOTP using OP-TEE")

##  Client / Server (OP-TEE)?
Even though the current implementation works as a HOTP client, there is nothing
saying that the implementation cannot be updated to also work as the validating
server. One could for example have a simple device (a [security token] only
generating one time passwords) and use the TEE as a validating service to open
up other secure services.

[HMAC]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
<!--- The link below to mscgen.js.org should be updated when regenerating the image -->
[link to sequence diagram]: https://mscgen.js.org/?lang=xu&msc=msc%20%7B%0A%20%20wordwraparcs%3Doff%2C%0A%20%20hscale%3D%220.95%22%2C%0A%20%20watermark%3D%22HOTP%20OP-TEE%20%22%3B%0A%0A%20%20tee%20%5Blabel%3D%22TEE%20%2F%20TA%22%2C%20linecolor%3D%22darkgreen%22%2C%20textcolor%3D%22white%22%2C%20textbgcolor%3D%22darkgreen%22%2C%20arclinecolor%3D%22darkgreen%22%2C%20arctextcolor%3D%22darkgreen%22%5D%2C%0A%20%20client%20%5Blabel%3D%22Client%22%2C%20linecolor%3D%22darkgreen%22%2C%20textcolor%3D%22white%22%2C%20textbgcolor%3D%22darkgreen%22%2C%20arclinecolor%3D%22darkgreen%22%2C%20arctextcolor%3D%22darkgreen%22%5D%2C%0A%20%20server%20%5Blabel%3D%22Server%22%2C%20linecolor%3D%22%233a5795%22%2C%20textcolor%3D%22white%22%2C%20textbgcolor%3D%22%233a5795%22%2C%20arclinecolor%3D%22%233a5795%22%2C%20arctextcolor%3D%22%233a5795%22%5D%3B%0A%20%20%0A%20%20client%20note%20client%20%5Blabel%3D%22Shared%20key%20needs%5Cnto%20be%20handled%5Cnusing%20secure%5Cnchannels%20(TLS%2FSSL)%22%5D%3B%0A%20%20client%20%3C%3D%3E%20server%20%5Blabel%3D%22Agree%20on%20shared%20key%22%5D%3B%0A%20%20client%20%3D%3E%20tee%20%5Blabel%3D%22Store%20shared%20key%22%5D%3B%0A%20%20client%20%3D%3E%20server%20%5Blabel%3D%22Login%22%5D%3B%0A%20%20server%20%3D%3E%20client%20%5Blabel%3D%22Request%20HOTP%22%5D%3B%0A%20%20client%20%3D%3E%20tee%20%5Blabel%3D%22Get%20HOTP%20from%20TEE%22%5D%3B%0A%20%20tee%20%3E%3E%20tee%20%5Blabel%3D%22Calulate%20HOTP%22%5D%3B%0A%20%20tee%20%3E%3E%20client%20%5Blabel%3D%22HOPT%20value%22%5D%3B%0A%20%20client%20%3E%3E%20server%20%5Blabel%3D%22Send%20HTOP%20value%22%5D%3B%0A%20%20server%20%3E%3E%20server%20%5Blabel%3D%22Calulate%20HOTP%20locally%22%5D%3B%0A%20%20client%20alt%20server%20%5Blabel%3D%22Client%20HOTP%20%3D%3D%20Server%20HOTP%3F%22%2C%20linecolor%3D%22grey%22%2C%20textbgcolor%3D%22white%22%5D%20%7B%0A%20%20%09%0A%20%20%20%20---%20%5Blabel%3D%22Yes%22%2C%20linecolor%3Dgrey%2C%20textbgcolor%3Dwhite%5D%3B%0A%20%20%20%20server%20%3E%3E%20client%20%5Blabel%3D%22Grant%20access%22%5D%3B%0A%20%20%20%20%0A%20%20%20%20---%20%5Blabel%3D%22No%22%2C%20linecolor%3Dgrey%2C%20textbgcolor%3Dwhite%5D%3B%0A%20%20%20%20server%20%3E%3E%20client%20%5Blabel%3D%22Access%20denied%22%5D%3B%0A%20%20%7D%3B%0A%7D
[RFC4226]: https://www.ietf.org/rfc/rfc4226.txt
[security token]: https://en.wikipedia.org/wiki/Security_token
[two factor authentication]: https://en.wikipedia.org/wiki/Multi-factor_authentication
