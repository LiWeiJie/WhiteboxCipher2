# WhiteboxCipher2 
## Required
* MatrixLib https://github.com/LiWeiJie/MatrixLibrary
* AisinoSSL
Check whether the corresponding library file exists in the Lib folder. If it does not exist, you need to compile it yourself.

## Build steps

```${build_target} could be macOS, win32, iOS```

```
mkdir build
cd build
cmake -DBUILD_TARGET=${build_target} ../
make
```

