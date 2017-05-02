### Summary
The goal of this project is to take a URL on the command line and downloads the associated file.
The implementation includes protocols from Data-link Layer to Application Layer with the basic raw socket.
The main work is about building the Ethernet, IP and TCP headers in each packet.
---
### Implementation of Each Layer:
Ethernet Header | IP Header |     TCP Header     | HTTP Data | Padding
             ---|---        |---                 |---        |---
    14 byte     |  20 byte  |   20 byte or more  |           |add to 64