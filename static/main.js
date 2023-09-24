function toggleDivDisplayById(id){
  var div = document.getElementById(id);
  if (div.style.display === "none") {
    div.style.display = "block";
  } else {
    div.style.display = "none";
  }
}

function toggleDivDisplayByClass(className){
  var div = document.getElementsByClassName(className);
  for (var i = 0; i < div.length; i++) {
    if (div[i].style.display === "none") {
      div[i].style.display = "block";
    } else {
      div[i].style.display = "none";
    }
  }
}


function toggleCollapseNavbar(){
    var x = document.getElementById("navbar");
    if (x.className === "navbar") {
      x.className += " responsive";
    } else {
      x.className = "navbar";
    }
}

function checkPassword(){
  // runs onkeyup
  var input_password = document.getElementById("password");
  var input_confirmPassword = document.getElementById("password_confirm");
  var password = input_password.value;
  var confirmPassword = input_confirmPassword.value;
  var message = document.getElementById("message");
  if ( message == null ){
    message = document.createElement("p");
    message.id = "message";
    input_confirmPassword.parentNode.appendChild(message);
  }
  if ( password == confirmPassword ){
    message.innerHTML = "Passwords Match";
    message.style.color = "green";
    // unblock submit
    document.getElementById("submit-button").disabled = false;
  }
  else{
    message.innerHTML = "Passwords Do Not Match";
    message.style.color = "red";
    // block submit
    document.getElementById("submit-button").disabled = true;
  }

}
