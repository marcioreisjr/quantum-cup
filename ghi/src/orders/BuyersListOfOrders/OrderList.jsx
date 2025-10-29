import { React, useState, useEffect } from "react";


function OrderList({ quantumAuth }) {
    const [ordersByBuyer, setOrdersByBuyer] = useState([])
    const [triggerRefresh, setTriggerRefresh] = useState(0)

    useEffect(() => {
        async function loadOrders() {
            try {
                const res = await fetch(quantumAuth.baseUrl + "/api/orders");

                if (res.ok) {
                    const data = await res.json();

                    const authentication = quantumAuth.getAuthentication();
                    if (authentication && authentication.account) {
                        const ordersForBuyer = data.orders.filter(order => order.buyer_id === authentication.account.id);
                        setOrdersByBuyer(ordersForBuyer);
                    }

                } else {
                    console.error('Failed to fetch products:', res.status);
                }
            } catch (error) {
                console.error('Error during orders fetch:', error);
            }
        };
        loadOrders()
    }, [quantumAuth, triggerRefresh])

    const handleDeleteClick = async (orderId) => {
        console.log('Deleting order with ID:', orderId);

        try {
            const response = await fetch(`${quantumAuth.baseUrl}/api/orders/${orderId}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            if (!response.ok) console.error('Failed to delete order:', response.status);
            setTriggerRefresh(triggerRefresh + 1)
        } catch (error) {
            console.log('Error during delete:', error);
        }
    };


    return (

        <div className="d-flex flex-column flex-md-row justify-content-around my-5">
            {/* left panel */}
            <div className="d-flex flex-column col-6 align-items-center">


                <h1 className="panel-title">Orders</h1>
                <div id="open-orders-id">
                    <div className="container">
                        <table className="table">
                            <thead>
                                <tr>
                                    <th scope="col">Orders</th>
                                    <th scope="col">Buyer</th>
                                    <th scope="col">Product</th>
                                    <th scope="col">Quantity</th>
                                    <th scope="col">Unit</th>
                                    <th scope="col">Price</th>
                                    <th scope="col">Total</th>
                                    <th scope="col">Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {ordersByBuyer.map((order, i) => (
                                    <tr key={i}>
                                        <th scope="row">{i + 1}</th>
                                        <td>{order.buyer_fullname}</td>
                                        <td>{order.product_name}</td>
                                        <td>{order.quantity}</td>
                                        <td>{order.unit}</td>
                                        <td>${order.price}</td>
                                        <td>${order.total}</td>
                                        <td>{order.status}</td>
                                        <td>
                                            <button onClick={() => { }}
                                                className="btn btn-sm"
                                                disabled={order.status === "cancelled"}
                                            >
                                                Edit
                                            </button>
                                        </td>
                                        <td>
                                            <button onClick={() =>
                                                handleDeleteClick(order.id)}
                                                className="btn btn-sm"
                                                disabled={order.status === "cancelled"}
                                            >
                                                Cancel
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
            <div className="d-flex flex-column align-items-center col-6 container">
                <div className="col-12 col-md-6 logo-signup">
                    <img src="https://i.imgur.com/zlzNSFj.png" alt="coffee log" className="img-fluid" referrerPolicy="no-referrer" />
                </div>
            </div>
        </div>
    );
}

export default OrderList;
