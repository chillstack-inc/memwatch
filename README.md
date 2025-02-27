# memwatch

## Overview
memwatch demonstrates real-time detection of self-modification in Android ARM64 program code segments using seccomp filters and ptrace. This tool monitors memory protection changes and detects self-modification attempts in real-time. Additionally, it is able to not only detect but also disable such self-modifications.

This tool was developed as a Proof of Concept (PoC) for the paper **"Extension of Detection and Avoidance Methods for Dynamic Function Call Tracing by Frida to Android Environment"** presented at The 87th National Convention of IPSJ.

[日本語のREADMEはここ](https://github.com/chillstack-inc/memwatch/blob/master/README.ja.md)

## Features
- **Selective Control of W^X Policy**: Monitoring changes to memory write/execute permissions and providing finely control approvals and denials
- **Real-time Intervention**: Detects and intervenes in process self-modification attempts in real-time
- **Two Response Modes**:
  - Skip Mode: Disables self-modifying code by skipping it
  - Control Mode: Temporarily grants permissions to execute a single instruction before restoring protection
- **Whitelist Support**: Handles exceptions for trusted functions such as Frida's Interceptor.attach (allows up to two mprotect calls)

## Project Structure
### Main Components
1. **memwatch.cpp** - C++ debugger component
   - Process monitoring using ptrace
   - SIGSEGV signal handling
   - Management and Control of Memory Protection
2. **install_seccomp.js** - Frida script
   - Configuration of seccomp filter
   - Whitelist function registration
   - Communication establishment with the debugger

## Execution
### Prerequisites
- ADB (Android Debug Bridge)
- Rooted Android device
- Frida CLI

### Setup
Transfer files to device and grant execution permission
```bash
adb push memwatch /data/local/tmp
adb shell chmod a+x /data/local/tmp/memwatch
```
Install the test application
```bash
adb install app-release.apk
```

Run the frida-server
```bash
adb shell
$ su
$ cd /data/local/tmp
$ ./frida-server
```


### Verification Patterns
The test app `hook_detector` verifies whether the `open` function in `libc.so` has been tampered with by pressing the "Start Detection" button.
The app also has a "Fix Hook" button that restores the open function to its original bytecode.

<img src="./images/no_hook.png" width="200" alt="No Hook Image">

#### Pattern 1: Frida Hook Only (without memwatch)
In this pattern, Frida's hook on the open function works normally and is detected by hook_detector.
1. **Apply Frida hook and run Start Detection**:
```bash
frida -U -f com.chillstack.hook_detector -l frida/open_hook.js
```
The hook is detected as shown below:

<img src="./images/do_hook.png" width="200" alt="Hook Image">

The "Fix Hook" button disables Frida's Interceptor.attach by restoring the code to its original state.

<img src="./images/fix_hook.png" width="200" alt="Fix Hook Image">

#### Pattern 2: Analyzing and Controlling Anti-Frida Protection
In this pattern, memwatch's seccomp filter is used to analyze and control the Anti-Frida self-modification protection mechanism.
1. **Launch memwatch in the background**:
```bash
adb shell
$ su
$ cd /data/local/tmp
# Skip mode (disable self-modification)
$ ./memwatch -s &
```
2. **Apply Frida hook and run Start Detection**:
```bash
frida -U -f com.chillstack.hook_detector -l frida/install_seccomp.js -l frida/open_hook.js
```
The hook is detected as shown below:

<img src="./images/do_hook.png" width="200" alt="Hook Image">

However, in this case, even after pressing the "Fix Hook" button, the code remains modified, and Frida's Interceptor.attach is still active.

<img src="./images/continue_hook.png" width="200" alt="Continue Hook Image">

## Technical Explanation
### Detection Flow
1. **Initial Setup**:
   - Frida script installs seccomp filter
   - Debugger connects to the process using ptrace
   - Whitelist information is shared via TCP communication (addresses used by Interceptor.attach, etc.)
2. **Permission Change Detection via seccomp Trap**:
   - Process requests write/execute permissions with mprotect
   - seccomp filter traps and notifies
   - Debugger selectively controls memory protection changes (allows whitelist addresses, restricts others)
3. **Write Attempt Detection via SIGSEGV Handling**:
   - SIGSEGV occurs on write attempts to protected memory
   - Debugger captures the signal
   - Controls based on configured mode (skip/control)

![](/images/flow.png)

## Key Features
- memwatch is a tool for analyzing and controlling Anti-Frida self-modification protection mechanisms, not for disabling Frida hooks
- For addresses registered in the whitelist, such as Frida's Interceptor.attach, up to two mprotect calls are allowed (Interceptor.attach makes two mprotect calls during initialization)
- To analyze self-modifying code behavior, SIGSEGV is captured and intervened in real-time

## Applications
- **Security Research**: Evaluation and analysis of Anti-Frida/Anti-Hook protection techniques
- **Malware Analysis**: Behavioral analysis of self-modifying malware

## Limitations
- Requires root privileges
- May be affected by kernel or hardware limitations
- May not support certain advanced hooking techniques such as Frida's Interceptor.replacement

## License
Apache License 2.0
