// are ya sure ya wanna do this?

document.addEventListener("DOMContentLoaded", function(event) {
  // connect all delete buttons
  connect_delete_buttons("delete_form");
  connect_delete_buttons("delete_anchor");
});

// all_delete_buttons = document.getElementsByClassName("delete_button");
// all_delete_forms = document.getElementsByClassName("delete_form");
default_yes_txt = "Yes";
default_no_txt = "No";
default_item_name = "<item_name>";

function connect_delete_buttons(parent_element_class){
  var button_parents = document.getElementsByClassName(parent_element_class);
  for (var i = 0; i < button_parents.length; i++) {
    var parent = button_parents[i];
    var delete_button = parent.getElementsByClassName("delete_button")[0];
    connect_delete_button(delete_button);
  }
}

function connect_delete_button(button){
  // connect a single delete button to popup confirmation dialog box and prevent fomr submission
  // get all the data from the button if it exists and set defaults if it doesn't
  var yes_txt = button.getAttribute("data-yes-txt");
  if (yes_txt == null){
    yes_txt = default_yes_txt;
  }
  var no_txt = button.getAttribute("data-no-txt");
  if (no_txt == null){
    no_txt = default_no_txt;
  }
  var item_name = button.getAttribute("data-item-name");
  if (item_name == null){
    item_name = default_item_name;
  }
  // attach the onclick event to the button
  button.onclick = function(event){
    return show_delete_confirmation(item_name, yes_txt, no_txt);
  }
  console.log("connected delete button");
}

function show_delete_confirmation(this_txt="item_name",yes_txt="Yes",no_txt="No") {
    var txt = "Are you sure you want to delete this " + this_txt + "?";
    var r = confirm(txt);
    if (r == true)
      return true;
  return false;
}
