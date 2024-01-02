document.addEventListener("DOMContentLoaded", function () {
    const openFormBtn = document.getElementById("openFormBtn");
    const closeFormBtn = document.getElementById("closeFormBtn");
    const popupForm = document.getElementById("popupForm");

    openFormBtn.addEventListener("click", function () {
        popupForm.style.display = "block";
    });

    closeFormBtn.addEventListener("click", function () {
        popupForm.style.display = "none";
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const closeFormBtn = document.getElementById("closeFormBtn");
    const profileBtn = document.getElementById("profileBtn");
    const profileForm = document.getElementById("profileForm");

    profileBtn.addEventListener("click", function () {
        profileForm.style.display = "block";
    });

    closeProfileFormBtn.addEventListener("click", function () {
        profileForm.style.display = "none";
    });
});