# Overview

[![Build Status](https://travis-ci.org/mschwager/duo_go.svg?branch=master)](https://travis-ci.org/mschwager/duo_go)
[![Coverage Status](https://coveralls.io/repos/github/mschwager/duo_go/badge.svg?branch=master)](https://coveralls.io/github/mschwager/duo_go?branch=master)

**duo_go** - Duo 2FA for Go web applications: https://duo.com/docs/duoweb

# Installing

```
$ go get github.com/mschwager/duo_go
```

# Using

Here's a short snippet of code demonstrating the library:

```go
package main

import (
    "fmt"
    "github.com/mschwager/duo_go"
)

func main() {
    duo_configuration := &duo_go.Web{
        Ikey: "<ikey-here>",
        Skey: "<skey-here>",
        Akey: "<akey-here>",
    }
    sig_request, _ := duo_go.SignRequest(duo_configuration, "example_username")

    fmt.Println("Signature request: " + sig_request)
}
```

```
$ go run example.go
Signature request: TX|ZXh...|5ce...:APP|ZXh...|fc2...
```

For a more complete example, checkout the demo code.

# Demo

Configure your `ikey`, `skey`, `akey`, and `host`, in `duo_go_demo.go`.

Then run the following command:

```
$ go run duo_go_demo/duo_go_demo.go
```

# Testing

```
$ go test
```
