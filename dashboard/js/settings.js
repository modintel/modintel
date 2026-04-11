function saveProfile() {
    const name = document.getElementById('display-name').value;
    const email = document.getElementById('email').value;
    showModal('Profile Saved', 'Profile updated: ' + name + ' (' + email + ')');
}