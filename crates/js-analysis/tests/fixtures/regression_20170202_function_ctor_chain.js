var shellFactory = Function("return WScript.CreateObject('WScript.Shell');");
var shell = shellFactory();
shell.Run("cmd /c echo hello");
