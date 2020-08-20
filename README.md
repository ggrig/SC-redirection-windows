# Smart Card redirection POC (Windows 10)

The Visual Studio 2017 solution is based on the following projects:
- https://github.com/adamrehn/websocket-server-demo
- https://github.com/SC-Develop/SCD_SMCAuthServer

The solution implements WebSocket server on Windows 10 and communicates to Ubuntu 18.04 WebSocket server through the JavaScript

## Testing it

 - The Ubuntu server is accessed with 'sc_server.com' domain name. Add entry for it to C:\Windows\System32\drivers\etc\hosts file
 - Run the server-demo.html from the JavaScript folder
 - Run the WebSocket-server-demo project in Visual Studio debugger
 - Run the Ubuntu server
 - Communicate to both servers from within the server-demo.html issuing commands with the buttons

## Cryptography

All crypto operations are supported with a locally stored private key and the certificate. The corresponding PKCS12 and PEM files are mysite.local.pfx & mysite.local.cer. This leverages "Microsoft Base Cryptographic Provider" which in turn is utilized by regular smart cards for Windows authentication.
See https://docs.microsoft.com/en-us/windows/win32/seccertenroll/cryptoapi-cryptographic-service-providers

## Smart Cards

The following is supported:
- identifying if a Smart Card is attached to the computer
- obtaining and showing certificates stored on a Smart Card

Ideally, the project would utilize the smart-cards for crypto operations as well. However, the only smart card available during the development was the developer's national ID. That particular smart card was supported by a custom Crypto Service Provider whose documentation was not accessible.
