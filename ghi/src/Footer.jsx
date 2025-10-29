import React from "react";

function Footer() {
  return (
    <footer className="footer">
      <div className="mb-3">
        <div className="row g-0 footer-panels">
          <div className="d-flex d-none d-md-block col-md-4">
            <img src="https://i.imgur.com/IFkxtPY.png" className="img-fluid " alt="Quantum Cup Logo" referrerPolicy="no-referrer" />
          </div>

          <div className="d-flex flex-column col-8">

            <div className="card-body col-md-6">
              <h4 className="card-title">Quantum Cup</h4>
              <p className="card-text">
                This project is centered around Web Development and is aimed at showcasing the implementation of various web technologies, including:
              </p>
              <ul>
                <li>User Authentication</li>
                <li>Back-end implemented with FastAPI</li>
                <li>Database integrated with MongoDB</li>
                <li>Front-end developed using React.</li>
              </ul>
            </div>

            <div className="card-body align-self-end col-md-6">
              <h5>Follow Us</h5>
              <div className="d-flex">
                <i className="fab fa-facebook m-3" aria-hidden="true"></i>
                <i className="fab fa-instagram m-3" aria-hidden="true"></i>
                <i className="fab fa-x m-3" aria-hidden="true"></i>
              </div>
            </div>

          </div>

        </div>
      </div>
    </footer>
  );
}

export default Footer;
