// Sanitised, non-executable fixture inspired by public CVE-2023-26369 analysis.
var backing = new ArrayBuffer(0x200);
var u32 = new Uint32Array(backing);
var f64 = new Float64Array(backing);
var corruptedLength = u32.length;
if (corruptedLength != backing.byteLength / 4) {
    // Marker-only emulation of OOB leak logic.
    var oob = true;
}
var leakBase = 0x140000000;
var gadgetBase = leakBase + 0x12340;
var returnAddress = gadgetBase + 0x50;
var rop = new DataView(backing);
for (var idx = 0; idx < 8; idx++) {
    rop.setUint32(idx * 4, returnAddress + idx * 0x10);
}
