# xrp-vanity

## To Compile
```
clang++ -O2 -std=c++1y -lssl -lcrypto -lpthread main.cpp
./a.out
```

## To use

To start with 4 threads, searching for prefix rXRP
```
./a.out 4 XRP
xrp-vanity
Searching Prefix: rXRP - Threads: 4

[2017-08-16 09:14:59] rXRPST9qbGics7DcAEFku4X3EqZYYhPAk => snz9xnr8SvBbCABoTjupDAa2zWCeF 
[18450/s]
```
