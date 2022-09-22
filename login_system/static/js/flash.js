function hide_flashed_messages() {
    var flashed_messages = document.getElementsByClassName("flash");

    if (flashed_messages.length > 0) {
        flashed_message = flashed_messages[0];
    
        // Hide flashed messages after 5 seconds
        remove_flash = setTimeout(function() {
            flashed_message.style.display = "None";
        }, 5000);
    }
};

function add_flash_message(message, category) {
    flash_div = document.createElement(
        "div"
    );
    flash_div.classList.add("flash");
    flash_div.classList.add(category);
    flash_div.innerHTML = "<p>" + message + "</p>";
    document.getElementById("wrapper").appendChild(flash_div);
    hide_flashed_messages();
};

hide_flashed_messages();