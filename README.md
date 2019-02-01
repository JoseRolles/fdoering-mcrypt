# fdoering-mcrypt

NodeJS module - migrated mcrypt.js from F. Doering jsmcrypt Version 0.1 ([https://code.google.com/archive/p/js-mcrypt/](https://code.google.com/archive/p/js-mcrypt/)).

*jsmcrypt version 0.1  -  Copyright 2012 F. Doering*

## Install with npm

```
npm install fdoering-mcrypt
```


## NodeJS Encrypt Example

```javascript
// Require
var mcrypt = require("fdoering-mcrypt");

// Pseudo key **DO NOT USE THIS**
var key = "12345678901234567890123456789012";
// Pseudo initialization vector (iv)
var iv = "abcdefghijklmnopqrstuv1234567890";

// Plaintext
var message = "Hello there!";

// Encrypt
var encrypted_binary = mcrypt.Encrypt(message, iv, key, "rijndael-256", "cbc");

// Convert to Base64 for transporting using Node.js native Buffer class.
var encrypted_base64 = Buffer.from(encrypted_binary, "binary").toString("base64");
```

## NodeJS Decrypt Example

```javascript
// Convert Base64 back to Binary
var encrypted_binary = Buffer.from(encrypted_base64, "base64").toString("binary");

// Decrypt
var plaintext = mcrypt.Decrypt(encrypted_binary, iv, key, "rijndael-256", "cbc");

// Remove padding
plaintext = plaintext.replace(/\0/g,'');

// Prints "Hello there!"
console.log(plaintext);
```
