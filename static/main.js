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

function makeDeleteReqest(url){
  var xhttp = new XMLHttpRequest();
  xhttp.open("DELETE", url, true);
  xhttp.send();
}

function makePutReqest(url,formId){
  var xhttp = new XMLHttpRequest();
  xhttp.open("PUT", url, true);
  xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  xhttp.send(document.getElementById(formId).serialize());
}
