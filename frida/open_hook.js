var openPtr = Module.findExportByName("libc.so", "open");

setTimeout(() => {
  Interceptor.attach(openPtr, {
    onEnter: function (args) {
      this.str1 = args[0].readUtf8String();
      console.log("[*] open called with arguments:");
      console.log("    path: " + this.str1);
    },
    onLeave: function (retval) {
      console.log("[*] open returned: " + retval.toInt32());
    },
  });
}, 1000);
