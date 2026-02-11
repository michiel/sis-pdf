// Sanitised, non-executable fixture inspired by public CVE-2023-21608 write-ups.
var sprays = [];
for (var i = 0; i < 256; i++) {
    sprays.push(new ArrayBuffer(0x1000));
}
var victim = sprays[42];
var view = new Uint8Array(victim, 0, 0x400);
for (var offset = 0; offset < 0x100; offset += 4) {
    view[offset] = 0x41;
}
var dv = new DataView(victim);
for (var j = 0; j < 16; j++) {
    dv.setUint32(j * 4 + 0x20, 0x41414141);
}
