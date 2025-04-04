function startTimer(duration) {
    var timer = duration, minutes, seconds;
    var display = document.getElementById('timer');
    var interval = setInterval(function () {
        minutes = parseInt(timer / 60, 10);
        seconds = parseInt(timer % 60, 10);
        minutes = minutes < 10 ? "0" + minutes : minutes;
        seconds = seconds < 10 ? "0" + seconds : seconds;
        display.textContent = "Осталось: " + minutes + ":" + seconds;
        if (--timer < 0) {
            clearInterval(interval);
            var form = document.querySelector('form');
            if(form) {
                form.submit();
            }
        }
    }, 1000);
}
