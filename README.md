# xrp-vanity

## To Compile
```
clang++ -O2 -oxrpvanity -std=c++1y -lssl -lcrypto -lpthread main.cpp prefix.cpp
```

## To use

### Arguments
```
./xrpvanity <Threads> <Prefix> <Prefix> <Prefix>
```

### Example
To start with 8 threads, searching for prefix rXRP and rWET
```
./xrpvanity 8 XRP rWET
xrp-vanity
Search Threads: 8

Prefix difficulty:              4553521 rXRP
Prefix difficulty:              4553521 rWET

[2017-08-19 20:36:53] rXRPmxYJkZv62ULvRbrGhsfsfgkFNhqQg => sh4tVp3FBCeda6WumVdhj43BuPWWL
[2017-08-19 20:38:40] rXRPpuecmxEVEjjbZoDe777UYg5tac9dH => saUk8nDtNevADo58Kc8y7raZFTRMd
[2017-08-19 20:39:22] rWETXYMtiF7qwAhCfURTqp1tytFiqPfvi => sh1ZFEi38oXyahqXfRbwt2HMKSxaJ
[37.38 Kkey/s][total 7394035][Prob 4.9%][50% in 39.2s]                         
```
