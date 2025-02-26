const whitelist = [
  Module.findExportByName(null, "open")
];

function install_seccomp(whitelist) {
  // Write whitelist data
  const whitelist_size = whitelist.length;
  const whitelist_ptr = Memory.alloc(whitelist_size * Process.pointerSize); // Allocate memory for pointer size
  let index = 0;
  for (const entry of whitelist) {
    // Write pointer to whitelist_ptr
    Memory.writePointer(
      whitelist_ptr.add(index * Process.pointerSize),
      ptr(entry)
    );
    index++;
  }

  // Resolve prctl address for CModule
  const prctlAddr = Module.findExportByName(null, "prctl");
  // Define seccomp syscall number for ARM64
  const __NR_seccomp = 277;
  // Get syscall address
  const syscallAddr = Module.findExportByName(null, "syscall");
  if (!syscallAddr) {
    console.log("Failed to find syscall function");
    return;
  }

  function connectDebugger(whitelist) {
    // Get addresses of necessary system call functions
    const socketAddr = Module.findExportByName(null, "socket");
    const connectAddr = Module.findExportByName(null, "connect");
    const sendAddr = Module.findExportByName(null, "send");
    const closeAddr = Module.findExportByName(null, "close");

    // Define as NativeFunction
    const socket = new NativeFunction(socketAddr, "int", ["int", "int", "int"]);
    const connect = new NativeFunction(connectAddr, "int", [
      "int",
      "pointer",
      "int",
    ]);
    const send = new NativeFunction(sendAddr, "int", [
      "int",
      "pointer",
      "int",
      "int",
    ]);
    const close = new NativeFunction(closeAddr, "int", ["int"]);

    // Create sockaddr_in structure
    const sockaddr = Memory.alloc(16); // sizeof(struct sockaddr_in)
    sockaddr.writeU16(2); // AF_INET
    // Set port number (12345 -> 0x3039)
    const portPtr = sockaddr.add(2);
    Memory.writeU8(portPtr, 0x30); // high byte
    Memory.writeU8(portPtr.add(1), 0x39); // low byte
    // Set IP address (127.0.0.1)
    const ipPtr = sockaddr.add(4);
    Memory.writeU8(ipPtr, 127);
    Memory.writeU8(ipPtr.add(1), 0);
    Memory.writeU8(ipPtr.add(2), 0);
    Memory.writeU8(ipPtr.add(3), 1);

    // Create socket
    const sock = socket(2 /* AF_INET */, 1 /* SOCK_STREAM */, 0);
    if (sock === -1) {
      console.log("[-] Failed to create socket");
      return;
    }
    console.log(`[+] Socket created: ${sock}`);

    // Connect
    if (connect(sock, sockaddr, 16) === -1) {
      close(sock);
      return;
    }

    // Send PID
    const pid = Process.id;
    const pidBuffer = Memory.alloc(4);
    pidBuffer.writeU32(pid);
    console.log(`[+] Sending notification with PID: ${pid}`);
    if (send(sock, pidBuffer, 4, 0) !== 4) {
      console.log("[-] Failed to send PID");
      close(sock);
      return;
    }

    // Send whitelist count
    const countBuffer = Memory.alloc(4);
    countBuffer.writeU32(whitelist.length);
    console.log(`[+] Sending whitelist count: ${whitelist.length}`);
    if (send(sock, countBuffer, 4, 0) !== 4) {
      console.log("[-] Failed to send whitelist count");
      close(sock);
      return;
    }

    // Send whitelist addresses
    const addrBuffer = Memory.alloc(8);
    for (const addr of whitelist) {
      addrBuffer.writePointer(addr);
      console.log(`[+] Sending whitelist address: 0x${addr.toString(16)}`);
      if (send(sock, addrBuffer, 8, 0) !== 8) {
        console.log("[-] Failed to send whitelist address");
        close(sock);
        return;
      }
    }
    console.log("[+] All data sent successfully");
    close(sock);
  }

  // JS side
  const cm = new CModule(
    `
    // Required constant definitions
    #define AUDIT_ARCH_AARCH64 0xC00000B7
    #define SECCOMP_MODE_FILTER 2
    #define SECCOMP_RET_KILL 0x00000000
    #define SECCOMP_RET_ALLOW 0x7fff0000
    #define SECCOMP_RET_TRACE 0x7ff00000
    #define PR_SET_NO_NEW_PRIVS 38
    #define PR_SET_SECCOMP 22
    #define __NR_mprotect_arm64 226
    // BPF macro definitions
    #define BPF_LD 0x00
    #define BPF_W 0x00
    #define BPF_ABS 0x20
    #define BPF_JMP 0x05
    #define BPF_JEQ 0x10
    #define BPF_K 0x00
    #define BPF_RET 0x06
    #define BPF_STMT(code, k) { code, 0, 0, k }
    #define BPF_JUMP(code, k, jt, jf) { code, jt, jf, k }
    #define SECCOMP_FILTER_FLAG_TSYNC 1
    #define SECCOMP_SET_MODE_FILTER 1
    // Structure definitions
    struct seccomp_data {
      int nr;
      unsigned int arch;
      unsigned long long args[6];
    };
    struct sock_filter {
      unsigned short code;
      unsigned char jt;
      unsigned char jf;
      unsigned int k;
    };
    struct sock_fprog {
      unsigned short len;
      struct sock_filter *filter;
    };
    // External function declaration for prctl pointer
    extern int prctl_impl(int option, unsigned long arg2, unsigned long arg3,
                          unsigned long arg4, unsigned long arg5);
    extern int seccomp_impl(int mode, int filter, void *prog);

    void install_seccomp_filter() {
      struct sock_filter filter[] = {
        // Verify ARM64 architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (unsigned int)&((struct seccomp_data *)0)->arch),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
        // Check for mprotect system call
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (unsigned int)&((struct seccomp_data *)0)->nr),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect_arm64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        // Check 4th argument (debug flag)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (unsigned int)&((struct seccomp_data *)0)->args[3]),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xDEADBEAF, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE)
      };
      struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter
      };
      // Set PR_SET_NO_NEW_PRIVS
      if (prctl_impl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return;
      }
      // Install seccomp filter
      if (seccomp_impl(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) == -1) {
        return;
      }
    }
    `,
    {
      prctl_impl: new NativeCallback(
        (option, arg2, arg3, arg4, arg5) => {
          return new NativeFunction(prctlAddr, "int", [
            "int",
            "uint64",
            "uint64",
            "uint64",
            "uint64",
          ])(option, arg2, arg3, arg4, arg5);
        },
        "int",
        ["int", "uint64", "uint64", "uint64", "uint64"]
      ),
      seccomp_impl: new NativeCallback(
        (operation, flags, args) => {
          return new NativeFunction(syscallAddr, "long", [
            "int", // syscall number
            "int", // operation
            "int", // flags
            "pointer", // args
          ])(__NR_seccomp, operation, flags, args);
        },
        "long",
        ["int", "int", "pointer"]
      ),
    }
  );

  const install_seccomp_filter = new NativeFunction(
    cm.install_seccomp_filter,
    "int",
    []
  );

  // Install filter
  const result = install_seccomp_filter();
  if (result === 0) {
    console.log("[+] Seccomp filter installed successfully");
    connectDebugger(whitelist);
  } else if (result === -1) {
    console.log("[-] Failed to set PR_SET_NO_NEW_PRIVS");
  } else if (result === -2) {
    console.log("[-] Failed to install seccomp filter");
  }
}

setTimeout(() => {
  install_seccomp(whitelist);
}, 100);
