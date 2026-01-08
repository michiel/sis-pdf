sourceCode = "gqn"; 
function decrypt(str, jump){
var result = "";
var list = str.split(',');
        for (var i=0; i < list.length; i++) {
            result +=  String.fromCharCode(list[i] - jump);
        }
        return result;
        }
eval(decrypt(sourceCode,(new Date().getSeconds() % 1)))
