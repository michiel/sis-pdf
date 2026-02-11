var state = 0;
while (true) {
    switch (state) {
        case 0:
            state = 1;
            break;
        case 1:
            state = 2;
            break;
        case 2:
            state = 3;
            break;
        case 3:
            break;
        default:
            state = 0;
            break;
    }
    if (state === 3) {
        break;
    }
}
