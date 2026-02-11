var p = sessionStorage.getItem('payload');
var base = btoa('alert(5)');
var decoded = atob(base);
Function(decoded)();
