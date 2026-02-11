var field = getField('f1');
var a = String.fromCharCode(97,108,101,114,116);
var b = String.fromCharCode(40,1,41);
var payload = a.concat(b);
app.eval(payload);
