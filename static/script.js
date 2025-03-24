document.getElementById("bookingForm").addEventListener("submit", function(event) {
    event.preventDefault();

    const fromLocation = document.getElementById("from_location").value;
    const toLocation = document.getElementById("to_location").value;
    const travelDate = document.getElementById("travel_date").value;

    if (!fromLocation || !toLocation || !travelDate) {
        alert("Please fill all fields!");
        return;
    }
    document.addEventListener("DOMContentLoaded", function() {
        document.getElementById("planeImage").src = "/static/image.jpeg";
    });
    
    // Send data to Flask backend
    fetch("https://flask-project-rbxx.onrender.com/search", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ from_location: fromLocation, to_location: toLocation, travel_date: travelDate })
    })
    .then(response => response.json())
    .then(data => alert(`Flights found: ${JSON.stringify(data)}`))
    .catch(error => console.error("Error:", error));
});
