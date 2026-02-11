var a = doc.getAnnots(0);
var base = btoa('alert(2)');
var staged = atob(base);
Function(staged)();
