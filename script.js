var frida = require('frida');

frida.attach("my_executable").then(function (session) {
  const script = session.createScript(`
    Interceptor.attach(Module.findExportByName("libc.so", "getaddrinfo"), {
      onEnter: function (args) {
        args[0] = ptr("0x7f000001"); // 127.0.0.1
      }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "read"), {
      onEnter: function (args) {
        if (args[2].toInt32() === 32) {
          Memory.writeByteArray(args[1], [0x01, 0x02, 0x03, 0x04, 0x05]);
        }
      }
    });
  `);
  script.load();
});
