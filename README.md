# Smart Card redirection POC (Windows 10)

## Introduction

The Visual Studio 2017 solution is based on the following projects:
- https://github.com/adamrehn/websocket-server-demo
- https://github.com/vakuum/tcptunnel

The solution implements WebSocket server on Windows 10 and communicates to Ubuntu 18.04 WebSocket server through the JavaScript module run in the browser

## Prerequisites

For Windows side USB/IP server, version [0.1.0](https://github.com/cezanne/usbip-win/releases/tag/v0.1.0) of USBIP-Win project has been tested 

1. Download and place the files into `C:\usbip` folder of the PC in your setup
2. Install test certificate
    - Install `C:\usbip\usbip_test.pfx` (password: usbip) 
    - Certificate should be installed into
    a. "Trusted Root Certification Authority" in "Local Computer" (not current user) and
    b. "Trusted Publishers" in "Local Computer" (not current user)
    Follow the [instruction](https://support.securly.com/hc/en-us/articles/360026808753-How-to-manually-install-the-Securly-SSL-certificate-on-Windows) for certificate installation
3. Switch the PC into test mode:
    - `> bcdedit.exe /set TESTSIGNING ON`
    - reboot the system
 
## Testing it

 - Follow the [instructions](https://github.com/cezanne/usbip-win/) to bind a USB device to usbip and expose it with usbip deamon.
 - The Ubuntu server is accessed with 'sc_server.com' domain name. Add entry for the DN name to C:\Windows\System32\drivers\etc\hosts file
 - Run the server-demo.html from the JavaScript folder
 - Unzip [server_binaries.zip](https://github.com/ggrig/SC-redirection-windows/blob/master/websocket-server-demo/server%20binaries.zip) into a folder and run the server
 - Run the Ubuntu [server](https://github.com/ggrig/SC-redirection-ubuntu)
 - Refresh server-demo.html (press F5 in Chrome)

