var a = doc.getAnnots(0);
var base = btoa('alert(12)');
var staged = atob(base);
Function(staged)();
