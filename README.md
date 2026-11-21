### 🮾 SOCKS Client Interface for Reticulum

#### How do I use this?
Drop the `SOCKSClientInterface.py` into your Reticulum interfaces folder ~(./reticulum/interfaces)

Then add an interface entry in your config like:


```
 [[RNS hidden service]]
   type = SOCKSClientInterface
   enabled = yes
   target_host = mycoolservice.onion
   target_port = 4242
   proxy_host = 127.0.0.1
   proxy_port = 9050
```
  The proxy defaults to `127.0.0.1:9050`



#### Options

  `connect_timeout = 120`
    Seconds to wait for the proxy to establish the connection to the target.

  ```
  proxy_username = name
  proxy_password = secret
  ```
  for 
    torrc authentication

