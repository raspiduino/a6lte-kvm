# Build and patch edk2
This note was based on [Arm's post](https://developer.arm.com/tools-and-software/open-source-software/firmware/edkii-uefi-firmware/building-edkii-uefi-firmware-for-arm-platforms/single-page)

## 1) Get a Linux machine
You can get a Linux PC, or WSL (Windows Subsystem for Linux), or any other x86/ARM computer that run Linux. This means you can even use your phone to build EDK II (if you have enough storage space)
<br> Other Unix or Windows can also be used to build this, but Linux is recommended. The notes here will apply to Linux distributions.

## 2) Create a directory for your work
Create a directory for your work. It's really important since during the build, things will be messed up!
<br> I recommend the name `source` since it's used in ARM's post, so you can just copy and paste some commands! (I'm too lazy for this :D)
<br> To to this:

```bash
mkdir source
cd source
export WORKSPACE=$PWD
```

## 3) Install tools
This depends on your Linux distribution.
<br> To do this in Debian based distributions (use `apt` / `dpkg` package manager):

```bash
sudo apt install git python3 python3-distutils uuid-dev build-essential bison flex
```

If you want to reduce the installation space, you can use `--no-install-recommends`.

## 4) Download the toolchain
To get the offical toolchain from ARM, go to [this web site](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-a/downloads)
<br> Select the toolchain that fit your host architecture. <b>Use `AArch64 ELF bare-metal target` target.</b>
<br> Download then extract it: (<i>for this example I will use the latest toolchain at the writing time</i>)

```bash
mkdir $WORKSPACE/toolchain
cd $WORKSPACE/toolchain
wget https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf.tar.xz
tar xf gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf.tar.xz
```

## 5) Clone the source code
```bash
cd $WORKSPACE
git clone https://github.com/tianocore/edk2-platforms.git
git clone https://github.com/acpica/acpica.git
git clone https://github.com/tianocore/edk2.git
cd edk2
git submodule update --init
cd ..
```

## 6) Build ACPICA
```bash
cd $WORKSPACE
make -C $WORKSPACE/acpica
```

If the build is too slow, you can use `make -C $WORKSPACE/acpica -j[NUMBER_OF_THREAD]`. For example, `make -C $WORKSPACE/acpica -j8`

## 7) Set the environment variables to build
```bash
export GCC5_AARCH64_PREFIX=$WORKSPACE/toolchain/[YOUR_TOOLCHAIN_FOLDER_NAME]/bin/aarch64-none-elf-
export PACKAGES_PATH=$WORKSPACE/edk2:$WORKSPACE/edk2-platforms
export IASL_PREFIX=$WORKSPACE/acpica/generate/unix/bin/
export PYTHON_COMMAND=/usr/bin/python3
```

For example:
```bash
export GCC5_AARCH64_PREFIX=$WORKSPACE/toolchain/gcc-arm-10.3-2021.07-x86_64-aarch64-none-elf/bin/aarch64-none-elf-
export PACKAGES_PATH=$WORKSPACE/edk2:$WORKSPACE/edk2-platforms
export IASL_PREFIX=$WORKSPACE/acpica/generate/unix/bin/
export PYTHON_COMMAND=/usr/bin/python3
```

## 8) Run build setup script
```bash
source edk2/edksetup.sh
make -C edk2/BaseTools -j8
```

## 9) Patch the source code
Download sleirsgoevy's patch to a file (eg `edk2.patch`), then run:
```bash
cd $WORKSPACE/edk2
git apply edk2.patch
```
Or you can apply it by hand! Read the patch and apply it using a text editor (it's not too long, so you can do this)

## 10) Build!
- To build the debug verison (produces more log, helpful for testing and debugging, but slower startup time):
```bash
cd $WORKSPACE/edk2
build -a AARCH64 -t GCC5 -p ArmVirtPkg/ArmVirtQemu.dsc -b DEBUG
```

- To build the release version (produce less log, faster startup time but harder to debug):
```bash
cd $WORKSPACE/edk2
build -a AARCH64 -t GCC5 -p ArmVirtPkg/ArmVirtQemu.dsc -b RELEASE
```

Wait for it to build... Have some coffee :)

## 11) Convert to QEMU's `pflash` format
QEMU by default use 64MB flash block, so you must convert the firmware to 64MB size.

- First find your built firmware :)
It's usually located at `$WORKSPACE/Build/ArmVirtQemu-AARCH64/<DEBUG|RELEASE>_GCC5/FV/*.fd`
<br> If I remembered well, then the file is `QEMU_EFI.fd`

- Then, create a 64MB flash binary:
```bash
dd if=/dev/zero bs=1M count=64 of=output.img
dd if=$WORKSPACE/Build/ArmVirtQemu-AARCH64/<DEBUG|RELEASE>_GCC5/FV/QEMU_EFI.fd bs=1M of=output.img conv=notrunc
```

I got this trick from some website, but I can't remember the name!
<br> So I found [this site](https://developer.r-project.org/Blog/content/post/2020-05-29-qemu-testing.html#:~:text=Prepare%20flash%20memory%20for%20boot%3A) also did the same trick!

Now you have `output.img` as the result image! Provide it to QEMU and QEMU will happily accept it!
<br> Good luck! If you have any questions, please contact me at the `Issue` tab. Bye.
