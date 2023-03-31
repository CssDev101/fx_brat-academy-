function signup() {
    var username = document.getElementById("username").value;
    var email = document.getElementById("email").value;
    var password = document.getElementById("password").value;

    // Check if the username, email, and password are valid
    if (username === "" || email === "" || password === "") {
      alert("Please fill out all fields.");
    } else if (!validateEmail(email)) {
      alert("Please enter a valid email address.");
    } else {
      alert("Signup successful!");
      // Save the user's information to a database or redirect to a confirmation page
    }
  }

  function validateEmail(email) {
    var re = /\S+@\S+\.\S+/;
    return re.test(email);
  }