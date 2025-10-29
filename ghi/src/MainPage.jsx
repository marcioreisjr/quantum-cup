import React, { useEffect } from "react";
import { useNavigate, Link } from 'react-router-dom';


function MainPage({ setAlert, quantumAuth }) {
  // redirect to the role page if authenticated
  const navigate = useNavigate();
  const authenticated = quantumAuth.isAuthenticated();

  useEffect(() => {
    async function checkLogin() {
      if (quantumAuth.isAuthenticated()) {
        navigate('/' + quantumAuth.getAuthentication().account.role);
      }
    }
    checkLogin();
  }, [quantumAuth, navigate]);

  // If authenticated, don't show anything
  if (authenticated) return null;

  return (
    <div>
      <div className="d-flex flex-column flex-md-row ">
        <div className="d-flex align-items-center hero-interaction flex-column col-12 col-md-6 ">
          <img src="https://i.imgur.com/jN2wPcE.png" alt="coffee logo" width={"33%"} className="mt-5" referrerPolicy="no-referrer"></img>
          <div className="h4 my-5 text-center">A unique community of coffee enthusiasts</div>
          <div className="d-flex">
            <Link className="btn" to="/signup">Sign Up</Link>
            <Link className="btn" to="/login">Login</Link>
          </div>
        </div>
        <div className="col-12 col-md-6">
          <img src="https://i.imgur.com/PgiFw0h.png" alt="coffee" width={"100%"} referrerPolicy="no-referrer"></img>
        </div>
      </div>
    </div>
  );
}

export default MainPage;
