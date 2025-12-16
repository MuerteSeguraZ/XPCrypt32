@echo off
setlocal

rem =============================
rem build script for libraries and tests
rem =============================

rem create build folders if they dont exist
if not exist build (
    mkdir build
)
if not exist build\objects (
    mkdir build\objects
)
if not exist output-tests (
    mkdir output-tests
)

rem check command line argument
if "%1"=="" (
    echo Usage: %0 --csprng ^| --hkdf ^| --chacha ^| --all ^| --clean ^| --info ^| --credits ^| --tests
    exit /b 1
)

if "%1"=="--clean" (
    echo Cleaning build folder...
    if exist build (
        del /q build\*.* 
        for /d %%D in (build\*) do rmdir /s /q "%%D"
        echo Build folder cleaned.
    )
    echo Cleaning output-tests folder...
    if exist output-tests (
        del /q output-tests\*.* 
        for /d %%D in (output-tests\*) do rmdir /s /q "%%D"
        echo Output-tests folder cleaned.
    )
    exit /b 0
)

if "%1"=="--csprng" (
    echo Building CSPRNG library...
    gcc -std=c99 -O2 -c csprng/csprng.c -o build\objects\csprng.o
    echo Object file created at: build\objects\csprng.o
    ar rcs build\libcsprng.a build\objects\csprng.o
    echo Done: build\libcsprng.a created.
    exit /b 0
)

if "%1"=="--hkdf" (
    echo Building HKDF+SHA512 library...
    gcc -std=c99 -O2 -c hkdf.c -o build\objects\hkdf.o
    echo Object file created at: build\objects\hkdf.o
    gcc -std=c99 -O2 -c sha512.c -o build\objects\sha512.o
    echo Object file created at: build\objects\sha512.o
    ar rcs build\libhkdf.a build\objects\hkdf.o build\objects\sha512.o
    echo Done: build\libhkdf.a created.
    exit /b 0
)

if "%1"=="--keccak" (
    echo Building Keccak ^(SHA3^) library...
    gcc -std=c99 -O2 -c keccak/keccak.c -o build/objects/keccak.o
    ar rcs build/libkeccak.a build/objects/keccak.o
    echo Done: build/libkeccak.a created.
    exit /b 0
)

if "%1"=="--chacha" (
    echo Building ChaCha20-Poly1305 library...
    gcc -std=c99 -O2 -c chacha20-poly1305/chacha20_poly1305.c -o build\objects\chacha.o
    echo Object file created at: build\objects\chacha.o
    gcc -std=c99 -O2 -c chacha20-poly1305/poly1305.c -o build\objects\poly1305.o
    echo Object file created at: build\objects\poly1305.o
    ar rcs build\libchacha.a build\objects\chacha.o build\objects\poly1305.o
    echo Done: build\libchacha.a created.
    exit /b 0
)

if "%1"=="--aes" (
    echo Building AES library...
    gcc -std=c99 -O2 -c aes/aes.c -o build/objects/aes.o
    ar rcs build/libaes.a build/objects/aes.o
    echo Done: build/libaes.a created.
    exit /b 0
)


if "%1"=="--all" (
    echo Building all libraries...
    call %0 --csprng
    call %0 --hkdf
    call %0 --chacha
    call %0 --keccak
    call %0 --aes
    exit /b 0
)

if "%1"=="--tests" (
    echo Building all tests into output-tests...
    rem ensure libraries exist
    call %0 --all
    if errorlevel 1 (
        echo Build stopped: one or more libraries failed to build.
        exit /b 1
    )

    rem test: test_vectors.c (HKDF/SHA)
    gcc -std=c99 -O2 test_vectors.c -Lbuild -lhkdf -o output-tests\test_vectors.exe
    if errorlevel 1 (
        echo Build stopped: test_vectors.exe failed
        exit /b 1
    )
    echo Test created: output-tests\test_vectors.exe

    rem test: csprng_test.c
    gcc -std=c99 -O2 csprng/csprng_test.c -Lbuild -lcsprng -o output-tests\csprng_test.exe
    if errorlevel 1 (
        echo Build stopped: csprng_test.exe failed
        exit /b 1
    )
    echo Test created: output-tests\csprng_test.exe

    rem test: ChaCha20-Poly1305 main.c
    gcc -std=c99 -O2 chacha20-poly1305/main.c -Lbuild -lchacha -o output-tests\test_chacha.exe
    if errorlevel 1 (
        echo Build stopped: test_chacha.exe failed
        exit /b 1
    )
    echo Test created: output-tests\test_chacha.exe

    rem test: keccak main.c
    gcc -std=c99 -O2 keccak/main.c -Lbuild -lkeccak -o output-tests\test_keccak.exe
    if errorlevel 1 (
        echo Build stopped: test_keccak.exe failed
        exit /b 1
    )
    echo Test created: output-tests\test_keccak.exe

    rem test: AES main.c
    gcc -std=c99 -O2 aes/main.c -Lbuild -laes -o output-tests\test_aes.exe
    if errorlevel 1 (
        echo Build stopped: test_aes.exe failed
        exit /b 1
    )
    echo Test created: output-tests\test_aes.exe

    echo All tests compiled successfully into output-tests.
    exit /b 0
)

if "%1"=="--info" (
    echo Build script for all XP libraries.
    echo Available commands:
    echo   --csprng   : Build the CSPRNG library.
    echo   --hkdf     : Build the HKDF+SHA512 library.
    echo   --chacha   : Build the ChaCha20-Poly1305 library.
    echo   --keccak   : Build the Keccak ^(SHA3^) library.
    echo   --aes      : Build the AES library with modes like ECB, CBC, CTR, OFB and XTS.
    echo   --all      : Build CSPRNG, HKDF+SHA512, and ChaCha20-Poly1305 libraries.
    echo   --tests    : Compile all test programs into output-tests.
    echo   --clean    : Clean the build folder.
    echo   --info     : Display this information.
    echo   --credits  : Show credits.
    exit /b 0
)

if "%1"=="--credits" (
    echo All libs were made by MuerteSeguraZ ^& PanoramicReviews.
    echo Thanks for using :D
    exit /b 0
)

echo Invalid argument: %1
echo Usage: %0 --csprng ^| --hkdf ^| --chacha ^| --all ^| --clean ^| --info ^| --credits ^| --tests
exit /b 1
