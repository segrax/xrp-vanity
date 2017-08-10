# xrp-vanity

## To use

Edit these lines in main.cpp. 'NUM_THREADS' and "rPrefix"

```
for (int i = 0; i < NUM_THREADS; i++) { 
    workers.push_back(std::thread(findkey, "rPrefix"));
}
```

## To Compile
```
clang++ -O2 -std=c++1y -lssl -lcrypto -lpthread main.cpp
./a.out
```
