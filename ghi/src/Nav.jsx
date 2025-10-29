import React, { useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import LogoutBtn from './logout/LogoutBtn';
import SearchBlock from './components/SearchBlock/SearchBlock';

function Nav({ quantumAuth }) {
  const [role, setRole] = React.useState('');

  useEffect(() => {
    if (quantumAuth.isAuthenticated()) {
      setRole(quantumAuth.getAuthentication().account.role);
    } else {
      setRole('');
    }
  }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    , [quantumAuth.isAuthenticated()]);


  return (
    <nav className="navbar navbar-expand-lg navbar-light mb-3 fixed-top">
      <div className="container-fluid">
        <NavLink className="navbar-brand fw-bold fs-3" to="/">
          <img src='https://i.imgur.com/IFkxtPY.png' height={"60px"} alt='logo' referrerPolicy="no-referrer" />
          Quantum Cup
        </NavLink>

        <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
          <span className="navbar-toggler-icon"></span>
        </button>

        <div className="collapse navbar-collapse" id="navbarSupportedContent">
          <ul className="navbar-nav me-auto mb-2 mb-lg-0">
            {/* Vendors dropdown menu */}
            {
              role === 'vendor' &&
              <li className="nav-item dropdown">
                <NavLink className="nav-link dropdown-toggle btn" href="/" role="button"
                  data-bs-toggle="dropdown" aria-expanded="false">
                  Vendor Menu
                </NavLink>
                <ul className="dropdown-menu shadow rounded-3">
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/vendor">Vendor Home Page</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/createproduct">Create Product</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/products">List Products</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/vendor/product">Manage Products</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/vendor/orders">Manage Orders</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn d-flex justify-content-center">
                      {
                        /* Logout button */
                        quantumAuth.isAuthenticated() &&
                        <LogoutBtn quantumAuth={quantumAuth} />
                      }
                    </NavLink>
                  </li>
                </ul>
              </li>
            }

            {/* buyers dropdown menu */}
            {
              role === 'buyer' &&
              <li className="nav-item dropdown">
                <NavLink className="nav-link dropdown-toggle btn" href="/" role="button"
                  data-bs-toggle="dropdown" aria-expanded="false">
                  Buyer Menu
                </NavLink>
                <ul className="dropdown-menu">
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/buyer">Buyer Home Page</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/products">List Products</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/buyer/orders">List Orders</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn" to="/vendors">List Vendors</NavLink>
                  </li>
                  <li className="dropdown-item">
                    <NavLink className="nav-link btn d-flex justify-content-center">
                      {
                        /* Logout button */
                        quantumAuth.isAuthenticated() &&
                        <LogoutBtn quantumAuth={quantumAuth} />
                      }
                    </NavLink>
                  </li>
                </ul>
              </li>
            }
          </ul>
          {
            /* Search box */
            quantumAuth.isAuthenticated() &&
            <SearchBlock placeholder="Search for products" quantumAuth={quantumAuth} />
          }
        </div>
      </div>
    </nav>
  )
}

export default Nav;
