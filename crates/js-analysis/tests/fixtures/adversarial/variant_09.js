var src = getField('n');
var chunks = ['%61%6c', '%65%72%74%28%39%29'];
var materialised = unescape(chunks[0] + chunks[1]);
app.eval(materialised);
