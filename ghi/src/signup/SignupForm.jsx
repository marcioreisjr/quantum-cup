import { React, useState } from "react";
import { useNavigate } from 'react-router-dom';
import login from "../login/login";
import "./SignupForm.css";


function SignupForm({ setAlert, quantumAuth }) {
  const navigate = useNavigate();
  const [role, setRole] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [email, setEmail] = useState('');
  const [fullname, setFullname] = useState('');
  const [street, setStreet] = useState('');
  const [city, setCity] = useState('');
  const [state, setState] = useState('');
  const [zipcode, setZipcode] = useState('');


  /**
   * Handles the form submission for login.
   * @param {Event} e - The event object.
   */
  async function handleSubmit(e) {
    e.preventDefault();
    if (password !== confirmPass) {
      setAlert('Passwords do not match');
      return;
    }
    const data = {
      role,
      // username is a combination of username and role
      username: `${username}::${role}`,
      password: password.slice(0, 72),  // Truncate to 72 chars for bcrypt
      email,
      fullname,
      street,
      city,
      state,
      zipcode
    }
    const URL = quantumAuth.baseUrl + "/signup";
    const create = await fetch(URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data),
      mode: 'cors',
      credentials: 'include'
    })
    if (create.status !== 200) return setAlert((await create.json()).detail);
    const loginRes = await login(quantumAuth, username, password, role);
    if (!loginRes.success) return setAlert(loginRes.msg);
    e.target.reset();
    navigate('/' + role);
  }

  /**
   * Handles the change event for the form.
   */
  function handleOnChangeForm(e) {
    switch (e.target.id) {
      case "buyer": // fallback on next case
      case "vendor":
        setRole(e.target.value);
        break;
      case "username":
        setUsername(e.target.value);
        break;
      case "password":
        setPassword(e.target.value);
        break;
      case "confirm-pass":
        setConfirmPass(e.target.value);
        break;
      case "email":
        setEmail(e.target.value);
        break;
      case "fullname":
        setFullname(e.target.value);
        break;
      case "street":
        setStreet(e.target.value);
        break;
      case "city":
        setCity(e.target.value);
        break;
      case "state":
        setState(e.target.value);
        break;
      case "zipcode":
        setZipcode(e.target.value);
        break;
      default:
        break;
    }
  }

  // no need to login if authenticated
  if (quantumAuth.isAuthenticated()) {
    navigate('/' + quantumAuth.getAuthentication().account.role);
  }
  return (
    <div className="container">
      <div className="d-flex flex-column flex-md-row">
        <div className="col-12 col-md-6">
          <form onSubmit={handleSubmit} onChange={handleOnChangeForm} id="sign-up-form">
            {/* sign selector */}
            <div className="d-flex mb-5">
              <div className="col-6 h2">Sign Up</div>
              <div className="form-check col-6 d-flex justify-content-between align-items-center">
                <div>
                  <input className="form-check-input" type="radio" required name="role" id="buyer" value="buyer" />
                  <label className="form-check-label" htmlFor="buyer">Buyer</label>
                </div>
                <div>
                  <input className="form-check-input" type="radio" required name="role" id="vendor" value="vendor" />
                  <label className="form-check-label" htmlFor="vendor">Vendor</label>
                </div>
              </div>
            </div>
            {/* actual form */}
            <div className="d-flex justify-content-between mb-3">
              <div className="col-5">
                <input type="text" className="form-control" id="username" required placeholder="Username" />
              </div>
              <div className="col-5">
                <input type="password" className="form-control" id="password" required placeholder="Password" />
              </div>
            </div>
            <div className="d-flex justify-content-between mb-3">
              <div className="col-5"></div>
              <div className="col-5">
                <input type="password" className="form-control" id="confirm-pass" required placeholder="Confirm Password" />
              </div>
            </div>
            <div className="mb-3">
              <input type="email" className="form-control" id="email" required placeholder="Email" />
            </div>
            <div className="mb-3">
              <input type="text" className="form-control" id="fullname" required placeholder="Full Name" />
            </div>
            <div className="mb-3">
              <input type="text" className="form-control" id="street" required placeholder="Street" />
            </div>
            <div className="mb-3">
              <input type="text" className="form-control" id="city" required placeholder="City" />
            </div>
            <div className="d-flex justify-content-between mb-5">
              <div className="col-5">
                <input type="text" className="form-control" id="state" required placeholder="State" />
              </div>
              <div className="col-5">
                <input type="number" className="form-control" id="zipcode" required placeholder="Zip Code" />
              </div>
            </div>
            <button className="btn">Sign Up</button>
          </form>
        </div>
        <div className="col-12 col-md-6 logo-signup">
          <img src="https://i.imgur.com/zlzNSFj.png" alt="coffee log" width={"70%"} referrerPolicy="no-referrer"></img>
        </div>
      </div>
    </div>
  )
}

export default SignupForm;
