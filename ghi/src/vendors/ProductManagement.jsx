import { React, useState, useEffect } from "react";
import { Link } from "react-router-dom";
import "./VendorPage.css";

function ProductManagement({ quantumAuth, handleClick }) {
    const [productsByVendor, setProductsByVendor] = useState([]);
    const [triggerRedraw, setTriggerRedraw] = useState(0);

    useEffect(() => {
        async function loadProducts() {
            // if not authenticated, do nothing
            if (!quantumAuth.getAuthentication() ||
                !quantumAuth.getAuthentication().account) return;
            const uid = quantumAuth.getAuthentication().account.id;

            try {
                const res = await fetch(quantumAuth.baseUrl + "/api/products");
                if (res.ok) {
                    const data = await res.json();
                    // filter products by vendor id
                    const productsForVendor = data.products.filter(
                        product => product.vendor_id === uid);
                    setProductsByVendor(productsForVendor);
                } else {
                    console.error('Failed to fetch products:', res.status);
                }
            } catch (error) {
                console.error('Error during product fetch:', error);
            }
        }

        loadProducts();
    }, [quantumAuth, triggerRedraw]);


    const handleDeleteClick = async (productId) => {
        try {
            const response = await fetch(`${quantumAuth.baseUrl}/api/products/${productId}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            if (response.ok) {
                // You can show a success message or update the product list after deletion
                setTriggerRedraw(triggerRedraw + 1);
            } else {
                // Handle error, show an error message
                console.error('Failed to delete product:', response.status);
            }
        } catch (error) {
            console.error('Error during delete:', error);
        }
    };

    return (
        <div className="d-flex flex-column flex-md-row justify-content-around my-5">
            {/* left panel */}
            <div className="d-flex flex-column col-8 align-items-center">
                <h1 className="panel-title">Products</h1>
                <div id="open-orders-id">
                    <div className="container">
                        <table className="table">
                            <thead>
                                <tr>
                                    <th scope="col">ID</th>
                                    <th scope="col">Name</th>
                                    <th scope="col">Description</th>
                                    <th scope="col">Unit</th>
                                    <th scope="col">Price</th>
                                    <th scope="col">Rating</th>
                                    <th></th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                {productsByVendor.map((product, i) => (
                                    <tr key={i}>
                                        <th scope="row">{i + 1}</th>
                                        <td>{product.name}</td>
                                        <td>{product.description}</td>
                                        <td>{product.unit}</td>
                                        <td>{product.price}</td>
                                        <td>{product.rating_count ? Math.round(product.rating_sum / product.rating_count) : 0}</td>
                                        <td>
                                            <Link
                                                role="button"
                                                id="product-mgmt-btn"
                                                to={`/product/edit/${product.id}`}
                                            >
                                                <button
                                                    onClick={() => handleClick(product)}
                                                    className="btn btn-sm"
                                                >
                                                    Edit
                                                </button>
                                            </Link>
                                        </td>
                                        <td>
                                            <button onClick={() => handleDeleteClick(product.id)} className="btn btn-sm">
                                                Delete
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            {/* right panel */}
            <div className="d-flex flex-column align-items-center col-4 container">
                <div className="col-12 col-md-6 logo-signup">
                    <img src="https://i.imgur.com/zlzNSFj.png" alt="coffee log" className="img-fluid" referrerPolicy="no-referrer" />
                </div>
                <div className="col-12 col-md-6 logo-signup">
                    <Link role="button" id="product-mgmt-btn" className="btn btn-lg text-center w-100" to="/createproduct">
                        Add Product
                    </Link>
                </div>
            </div>
        </div>
    );
}

export default ProductManagement;
