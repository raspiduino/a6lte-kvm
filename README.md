# Kernel source for SM-A600G (Samsung Galaxy A6 with exynos7870) with KVM support.

Warning: Super long text ahead, be careful not to mess up your brain :))

The FIRST thing to do BEFORE doing ANYTHING is to backup your data!

## DISCLAIMER

```
Your warranty is now void. It might be vaild again if you flash stock firmware from Samsung Smart Switch or firmware from [samfw.com](https://samfw.com/), but I am NOT sure.

I am not responsible for bricked devices, dead SD cards,
thermonuclear war, or you getting fired because the alarm app failed. Please
do some research if you have any concerns about features included in this
kernel before flashing it! YOU are choosing to make these modifications, and if
you point the finger at me for messing up your device, I will laugh at you.
```
Disclaimer template credit: [XDA forum](https://forum.xda-developers.com/) :)

## Status
It worked!
<br>![KVM!](https://user-images.githubusercontent.com/68118236/132131451-47ec72d8-f084-42ba-9899-9da26611b9b1.png)
<br>I will soon update a new screenshot.

## What is this?
This is the stock kernel source for SM-A600G, originally from [Samsung Opensource page](https://opensource.samsung.com/uploadSearch?searchValue=sm-a600g) with the file `SM-A600G_SEA_PP_Opensource.zip`, and the source has been patched for KVM support (so you can run VMs on your phone with `qemu-kvm`).

## Why?
For running VMs on your phone, probably Windows 10/11 ARM :) , but we need to patch the guess OS first. See XDA thread.

## How?
Originally from @sleirsgoevy 's patch for SM-A600FN [here](https://github.com/sleirsgoevy/exynos-kvm-patch)
<br>The XDA discussion can be found [here](https://forum.xda-developers.com/t/is-samsung-galaxy-a6-exynos-7870-suppor-kvm.4295775/)

## Download
In case you don't want to build it yourself, I have built one for you in [release](https://github.com/raspiduino/a6lte-kvm/releases)
<br>Trust me, there are absolutely no virus here :). Why should one insert a virus into an opensource project?

## Known bugs
- You cannot set any type of lock screen. This is Magisk bug. You can try some solutions [here](https://github.com/topjohnwu/Magisk/issues/1794). I cannot confirm (yet) if any of solutions in the link work. No lock screen means less security. You can develop your own app to replace the lock screen (I might make one some day) or you can use the lock screen feature on Game Booster on the bottom right of Linux Deploy app.
- Power button cannot wake phone up if you put it into lockscreen mode. You can still turn on the phone using power button, capture the screen using power button + volume down but screen capture menu won't open. Temporary fix for this: install black screen app on Google Play. I don't know what's best, you have to try :) I use [this one](https://play.google.com/store/apps/details?id=in.binarybox.blackscreen), just randomly picked :)
- If you turn your phone into lockscreen mode, power button cannot wake up your phone (see the above bug). To reset your phone, hold power button + volume down for 7 sec and it will reset. If you hold for 18 sec, it will come to "Force download mode", and you have to hold power button + volume down for 7 sec again.
- Volume up/down won't open volume menu when you click them, but they still work.
- The kernel only detect 4 cores / 8 cores of the Exynos 7870 SoC. I will try to fix this. In the log I can found some lines about `failed to hotplug cpu 4`. Maybe there is something I turn of by mistake when `make menuconfig`. You might not face this.
- @sleirsgoevy confirm that Linux boot on KVM but require special patch for DTB (device tree blob), Windows not boot (yet).
- On first boot, Chrome won't work. You have to update Chrome on Google Play, then it will work.
- There will be some notifications about "Unauthorize action...", just ignore it. It's just Samsung stock ROM detect root. If you feel annoying, try [Security log agent fix](https://play.google.com/store/apps/details?id=disable.securitylogagent.com.securitylogagentfix). Update: link is dead, use [this](https://github.com/kakopappa/SecurityLogAgentFix) instead.

## UPDATE
- 16/2/2022: There is a bug in `dtc` tool, you should refer to [this comment](https://www.reddit.com/r/LineageOS/comments/hkq8ah/comment/fxk7a8u/?utm_source=share&utm_medium=web2x&context=3) to patch `dtc`. A fix will be released in this repo later!
- 20/2/2022: Windows ARM requires some registers to be trapped. See [this](https://github.com/raspiduino/a6lte-kvm/blob/main/winarm64.md) for more details.

## Building
You can use the precompiled and patched img file at [release](https://github.com/raspiduino/a6lte-kvm/releases) to skip Building :)

- Step 0: Get a Linux PC (or WSL). If you don't have one, use the FREE [Google Cloud Shell](https://shell.cloud.google.com/) with a lot of preinstalled tools (and may also faster than your computer :D)
- Step 1: Get the toolchain by `git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9 && cd aarch64-linux-android-4.9 && git checkout ndk-release-r19`. Also install `bc` if you don't have it yet. On Debian-based distributions use `sudo apt install bc`, on Redhat-based use `sudo rpm install bc`
- Step 2: Clone this repo by `cd .. && git clone https://github.com/raspiduino/a6lte-kvm && cd a6lte-kvm`
- Step 3: Setup environment variable `export CROSS_COMPILE=../aarch64-linux-android-4.9/bin/aarch64-linux-android- ANDROID_MAJOR_VERSION=p ARCH=arm64`
- Step 4: Make menuconfig by `make exynos7870-a6lte_defconfig && make menuconfig`
- Step 5: Goto `Boot options` and then turn off all options which has `TIMA` and `RKP`. Then click exit to go back to main menu. Enable `Virtualization` by pressing the space key. Goto `Virtualization` menu and enable `Kernel-based Virtual Machine (KVM) support`. After that, exit menuconfig and save `.config` file.
- Step 6: Run `make Image -j8` to build. You can replace `-j8` by `-j[NUMBER OF THREAD TO RUN]`
- Step 7: Download [latest Magisk apk](https://github.com/topjohnwu/Magisk/releases/) and change the `.apk` extension to `.zip`. Extract zip and look into `lib` here you can find the binary tools for your architecture. On PC you extract `lib/x86/libmagiskboot.so`
- Step 8: You need to extract the stock `boot.img` from stock rom. You can get stock rom from [samfw.com](https://samfw.com/) or from my release page :). Then use `magiskboot unpack boot.img`, replace stock kernel with our compiled `Image` in `arch/arm64/boot/Image` and repack `boot.img` using `magiskboot repack boot.img new-boot.img`
- Step 9: Open your phone (or any phone), install [latest Magisk apk](https://github.com/topjohnwu/Magisk/releases/). Open the Magisk app, select Install, click Next, choose patch a file, then transfer the new-boot.img to that phone, patch it using Magisk. The output should be in Download folder.

Or all in one line to build but not patch :). I will include the build script later...
```bash
git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9 && cd aarch64-linux-android-4.9 && git checkout ndk-release-r19 && sudo apt install bc && cd .. && git clone https://github.com/raspiduino/a6lte-kvm && cd a6lte-kvm && export CROSS_COMPILE=../aarch64-linux-android-4.9/bin/aarch64-linux-android- ANDROID_MAJOR_VERSION=p ARCH=arm64 && make exynos7870-a6lte_defconfig && make menuconfig && make Image -j8
```

## Installing
After get the patched img file, it's now time for installing.

- Step 1: Transfer the patched img file to your Windows PC (to use Odin, in Linux you need [Heimdall](https://github.com/Benjamin-Dobell/Heimdall)) and rename it to `boot.img`. Add the file to tar using 7-zip or `tar` command then load `tar` file to AP in Odin. Flash your phone and when it says `PASS!`, you are doing well!
- Step 2: It will automatically reboot your phone and come with a screen say "Unable to verify your phone, please reset...", accept and reset it. After reset it will lead you to Android setup, just setup the device but DO NOT set any kind of password or screen lock.
- Step 3: After get into Android, open Magisk app in App list and allow it to install (and reboot). After reboot open Magisk app again, select Extension, search for "SELinux Permissive" and install it and allow it to reboot.
- Step 4: After reboot, open Play Store and install [Linux Deploy](https://play.google.com/store/apps/details?id=ru.meefik.linuxdeploy&hl=vi&gl=US) and VNC viewer (I recommend RealVNC's). Open Linux Deploy app, goto "Configure" and select Debian distro, arch armhf, <b>set username to `root`, set the password for it</b> then enable SSH and VNC. Come back to main menu and click Install. Wait for 10 minutes and when it says "Deploy!", click the play button to deploy it. Note: you can also select the arch to be arm64, but this often failed with `cannot find /system/bin/sh` (eventhough it's right there) or `Bad system call`. So use armhf for sure :). Why this fail? Well, Samsung release this phone with aarch64 kernel but aarch32 Android system! See more at [XDA thread](https://forum.xda-developers.com/t/is-samsung-galaxy-a6-exynos-7870-suppor-kvm.4295775/post-85580891).
- Step 5: Open VNC app, connect to `localhost:5900`. Enter the password you have set for root account. This should bring up a desktop environment. Open terminal, run `dpkg --add-architecture arm64` then `apt update` then `apt install qemu-system-arm:arm64 -y`. Let it do its job for a few minutes. After installing, run `chmod 666 /dev/kvm`.
- Step 6: QEMU KVM should work now, to test that, use `qemu-system-aarch64 -M virt -cpu host --enable-kvm -monitor stdio`. Then a QEMU monitor prompt should bring up. Type `info kvm`. If it return `kvm support: enabled`, then congratulation! You now have KVM on your phone!
- Step 7: Go and try Windows 10 or 11 ARM!
- Step 8: In case something wrong, you can always reflash stock `boot.img` to undo anything :)

**Remember: If you can get into Download mode in your Samsung phone, it will NEVER brick :)** . I have reflashed my Samsung phone with stock rom 3 times when trying this :) so don't be panic, it WON'T help :)

## Booting OSes on KVM
This instruction will be updated later, so don't worry :)
- Linux now boot with a custom DTB. See how to boot [here](Post in thread 'Is Samsung Galaxy A6 (Exynos 7870) suppor KVM?' https://forum.xda-developers.com/t/is-samsung-galaxy-a6-exynos-7870-suppor-kvm.4295775/post-85601873)
- U-boot with EFI support now boot
- EDK2 (or OVMF) works with a patch.
- 32-bit ARM (AArch32) not boot
- Windows not tested. I am working on a patch for it.
- MacOS on ARM is not tested until someone finds a way for booting it on QEMU.
- ReactOS port for ARM will be tested soon.

## Why root?
- You need root to run KVM or to access `/dev/kvm`
- Linux Deploy is based on `chroot`, which will provide access to hardware so it will require root.
  The opposite is Termux, it uses proot (emulate fake system call).

## License
See Linux's License [here](https://github.com/raspiduino/a6lte-kvm/blob/main/COPYING).

## Looking for original Linux kernel readme file? See it [here](https://github.com/raspiduino/a6lte-kvm/blob/main/README.kernel)
