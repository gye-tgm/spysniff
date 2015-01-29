# sPySniff

sPySniff does not require any external Python libraries, and can be
freely executed with a Python 2.7 interpreter.

The sniffer must be started as a root since it accesses the socket of
the system.

Hence, the user should start the sniffer with the following syntax. 

```
sudo ./spysniffer.py [PORT_1] [PORT_2] ... [PORT_N]
```

If you want the output of the sniffer to be stored into a file, just
use any pipe command on Linux.

sPySniff was tested and developed on a Ubuntu 14.04 machine, so we do
not guarantee that it works on any other distribution. 


