function saveProfile() {
    const name = document.getElementById('display-name').value;
    const email = document.getElementById('email').value;
    alert('Profile saved: ' + name + ' (' + email + ')');
}