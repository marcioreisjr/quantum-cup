import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Nav from "./Nav";
import MainPage from "./MainPage";
import Footer from './Footer';
import SignupForm from "./signup/SignupForm";
import LoginForm from "./login/LoginForm";
import VendorPage from "./vendors/VendorPage";
import BuyerPage from "./buyers/BuyerPage";
import BuyerReviews from "./buyers/BuyerReviews";
import LogoutBtn from './logout/LogoutBtn';
import ProductForm from './product/ProductForm';
import ProductList from "./product/ProductList"
import ProductDetail from './product/ProductDetail';
import { useEffect, useState } from "react";
import ProductManagement from './vendors/ProductManagement';
import OrderDetail from './orders/OrderDetail';
import OrderManagement from './vendors/OrderManagement';
import OrderForm from './orders/BuyersOrderForm/OrderForm';
import OrderList from './orders/BuyersListOfOrders/OrderList';
import VendorDetail from './vendors/VendorDetailPage';
import VendorList from './vendors/VendorList';

const baseUrl = import.meta.env.VITE_API_HOST;

function App() {
  const [showAlert, setShowAlert] = useState(false);
  const [alertMessage, setAlertMessage] = useState('');
  const [type, setType] = useState('');
  const [auth, setAuth] = useState(null);
  const [productData, setProductData] = useState()

  const setAuthentication = (auth) => setAuth(auth);
  const getAuthentication = () => JSON.parse(JSON.stringify(auth));
  const isAuthenticated = () => auth !== null;
  const quantumAuth = { setAuthentication, baseUrl, getAuthentication, isAuthenticated, };

  const domain = /https:\/\/[^/]+/;
  const basename = (import.meta.env.VITE_PUBLIC_URL || "").replace(domain, "");

  // send product data to form
  function handleClick(product) {
    setProductData(product)
  }

  /**
   * Handles the closing of the alert.
   */
  function handleAlertClose() {
    setShowAlert(false);
    setAlertMessage('');
  };

  /**
   * Sets the alert message and shows the alert. The user must dismiss this alert.
   *
   * @param {String} message - The message to display in the alert.
   * @param {Boolean} success - Whether the alert is a success or error alert.
   */
  function setAlert(message, success = false) {
    setAlertMessage(message);
    if (success) {
      setType('alert-success');
    } else {
      setType('alert-danger');
    }
    setShowAlert(true);
  }

  useEffect(() => {
    async function checkLogin() {
      try {
        const url = baseUrl + "/token";
        const res = await fetch(url, { method: "get", credentials: "include"});
        let auth = await res.json();
        quantumAuth.setAuthentication(auth);
      } catch {
        // no authentication yet
      }
    }
    checkLogin();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <BrowserRouter basename={basename}>
      <Nav quantumAuth={quantumAuth} />
      <div className='spacer'></div>
      {showAlert && !window.scrollTo(0, 0) && (
        <div className={"alert " + type + " alert-dismissible fade show"} role="alert">
          {alertMessage}
          <button type="button" className="btn-close" aria-label="Close" onClick={handleAlertClose}></button>
        </div>
      )}
      <div>
        <Routes>
          <Route path="/" element={<MainPage setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/buyer" element={<BuyerPage setAlert={setAlert} quantumAuth={quantumAuth} handleClick={handleClick} />} />
          <Route path="/buyer/orderform" element={<OrderForm productData={productData} setAlert={setAlert} quantumAuth={quantumAuth} auth={auth} />} />
          <Route path="/buyer/orders" element={<OrderList productData={productData} setAlert={setAlert} quantumAuth={quantumAuth} auth={auth} />} />
          <Route path="/buyer/reviews" element={<BuyerReviews setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/createproduct" element={<ProductForm setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/login" element={<LoginForm setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/logout" element={<LogoutBtn setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/product/edit/:productId" element={<ProductForm productData={productData} quantumAuth={quantumAuth} />} />
          <Route path="/products" element={<ProductList setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/orders/:id" element={<OrderDetail productData={productData} handleClick={handleClick} setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/products/:id" element={<ProductDetail productData={productData} handleClick={handleClick} setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/signup" element={<SignupForm setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/vendor" element={<VendorPage setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/vendor/:id" element={<VendorDetail setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/vendor/product" element={<ProductManagement setAlert={setAlert} handleClick={handleClick} quantumAuth={quantumAuth} />} />
          <Route path="/vendor/orders" element={<OrderManagement setAlert={setAlert} quantumAuth={quantumAuth} />} />
          <Route path="/vendors" element={<VendorList setAlert={setAlert} quantumAuth={quantumAuth} />} />
        </Routes>
      </div>
      <Footer />
    </BrowserRouter>
  )
}

export default App;
