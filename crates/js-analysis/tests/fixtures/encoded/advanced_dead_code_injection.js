function runner(flag) {
    if (false) {
        var hiddenA = "dead-branch-a";
        var hiddenB = "dead-branch-b";
    }
    if (0) {
        console.log("dead branch");
    }
    if (flag) {
        return;
        var neverReached = "dead-after-return";
    }
    throw new Error("stop");
    var deadAfterThrow = "dead-after-throw";
}
