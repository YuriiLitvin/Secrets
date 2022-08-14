
 const express = require("express");
 const bodyParser = require("body-parser");
 const ejs = require("ejs");

 const app = express();

app.use(express.static("public"));
app.use("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));









app.listen(3000, function() {
  console.log("Server is running on port 3000");
});
