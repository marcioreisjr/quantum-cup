
/**
 * Login to the server
 *
 * @param {*} quantumAuth - the authentication object
 * @param {*} username - the username of the user
 * @param {*} password - the password of the user
 * @param {*} role - the role of the user (buyer or vendor)
 * @returns {Object} - { success: Boolean, msg: String }
 */
async function login(quantumAuth, username, password, role) {
    const url = `${quantumAuth.baseUrl}/token`;
    const form = new FormData();
    form.append("username", username + "::" + role);
    form.append("password", password.slice(0, 72));
    let res;
    try {
        res = await fetch(url, {
            method: "post", credentials: "include",
            body: form
        });
    } catch (error) {
        res = await fetch(url, { method: "post", body: form });
    }
    if (res.status !== 200) return { success: false, msg: 'Invalid login' };
    res = await fetch(url, { method: "get", credentials: "include" });
    let auth = await res.json();
    quantumAuth.setAuthentication(auth);
    return { success: true, msg: null };
}

export default login;
