# Reticulum License
#
# Copyright (c) 2016-2026 Mark Qvist
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# - The Software shall not be used in any kind of system which includes amongst
#   its functions the ability to purposefully do harm to human beings.
#
# - The Software shall not be used, directly or indirectly, in the creation of
#   an artificial intelligence, machine learning or language model training
#   dataset, including but not limited to any use that contributes to the
#   training or development of such a model or algorithm.
#
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
#  Example:
#  [[RNS hidden service]]
#    type = SOCKSClientInterface
#    enabled = yes
#    target_host = mycoolservice.onion
#    target_port = 4242
#    proxy_host = 127.0.0.1
#    proxy_port = 9050
#
#   The proxy defaults to 127.0.0.1:9050
#
#   OPTIONAL PARAMETERS:
#   connect_timeout = 120
#     Seconds to wait for the proxy to establish the connection to the target.
#
#   reconnect_wait = 5
#     Seconds to wait before each attempt to reconnect, no less than
#     TCPClientInterface.RECONNECT_WAIT (5).
#
#   proxy_username = name
#   proxy_password = secret
#     torrc authentication
#


from RNS.Interfaces.TCPInterface import TCPClientInterface
from RNS.Interfaces.Interface import Interface
import ipaddress
import threading
import platform
import socket
import struct
import time
import RNS

class SOCKS5():
    VERSION       = 0x05
    AUTH_VERSION  = 0x01
    AUTH_NONE     = 0x00
    AUTH_USERPASS = 0x02
    AUTH_REFUSED  = 0xFF
    CMD_CONNECT   = 0x01
    ATYP_IPV4     = 0x01
    ATYP_DOMAIN   = 0x03
    ATYP_IPV6     = 0x04
    SUCCEEDED     = 0x00
    MAX_FIELD_LEN = 255

    REPLIES = { 0x01: "general proxy failure",
                0x02: "connection not allowed by proxy ruleset",
                0x03: "network unreachable",
                0x04: "host unreachable",
                0x05: "connection refused",
                0x06: "TTL expired",
                0x07: "command not supported",
                0x08: "address type not supported",
                0xF0: "onion service descriptor not found",
                0xF1: "onion service descriptor is invalid",
                0xF2: "onion service introduction failed",
                0xF3: "onion service rendezvous failed",
                0xF4: "onion service requires client authorization",
                0xF5: "onion service client authorization is wrong",
                0xF6: "invalid onion service address",
                0xF7: "onion service introduction timed out" }

    @staticmethod
    def address(host):
        try: ip = ipaddress.ip_address(host)
        except ValueError: ip = None

        if ip != None:
            if ip.version == 4: return bytes([SOCKS5.ATYP_IPV4])+ip.packed
            else:               return bytes([SOCKS5.ATYP_IPV6])+ip.packed

        try: name = host.encode("ascii")
        except UnicodeError: name = host.encode("idna")
        return bytes([SOCKS5.ATYP_DOMAIN])+SOCKS5.field("target_host", name)

    @staticmethod
    def field(option, value):
        if not isinstance(value, (str, bytes)): raise ValueError(f"The {option} option must be a single value, quote it if it contains commas")
        if isinstance(value, str): value = value.encode("utf-8")
        if not 0 < len(value) <= SOCKS5.MAX_FIELD_LEN: raise ValueError(f"The {option} option must be between 1 and {SOCKS5.MAX_FIELD_LEN} bytes long")
        return bytes([len(value)])+value


class SOCKSClientInterface(TCPClientInterface):
    DEFAULT_PROXY_HOST = "127.0.0.1"
    DEFAULT_PROXY_PORT = 9050

    # The default timeout. For tor this is 120 seconds, best left as default
    CONNECT_TIMEOUT    = 120

    def __init__(self, owner, configuration):
        c               = Interface.get_config_obj(configuration)
        name            = c["name"]
        target_host     = c["target_host"] if "target_host" in c else None
        target_port     = int(c["target_port"]) if "target_port" in c else None
        proxy_host      = c["proxy_host"] if "proxy_host" in c else SOCKSClientInterface.DEFAULT_PROXY_HOST
        proxy_port      = int(c["proxy_port"]) if "proxy_port" in c else SOCKSClientInterface.DEFAULT_PROXY_PORT
        proxy_username  = c["proxy_username"] if "proxy_username" in c else None
        proxy_password  = c["proxy_password"] if "proxy_password" in c else None
        connect_timeout = c.as_int("connect_timeout") if "connect_timeout" in c else SOCKSClientInterface.CONNECT_TIMEOUT
        reconnect_wait  = c.as_int("reconnect_wait") if "reconnect_wait" in c else SOCKSClientInterface.RECONNECT_WAIT

        if not target_host or target_port == None: raise ValueError(f"No target_host or target_port configured for interface \"{name}\"")
        if not isinstance(target_host, str):       raise ValueError(f"Invalid target_host configured for interface \"{name}\"")
        if not 0 < target_port < 65536:            raise ValueError(f"Invalid target_port configured for interface \"{name}\"")
        if not proxy_host or not isinstance(proxy_host, str): raise ValueError(f"Invalid proxy_host configured for interface \"{name}\"")
        if not 0 < proxy_port < 65536:             raise ValueError(f"Invalid proxy_port configured for interface \"{name}\"")
        if connect_timeout <= 0:                   raise ValueError(f"Invalid connect_timeout configured for interface \"{name}\"")
        if reconnect_wait < TCPClientInterface.RECONNECT_WAIT: raise ValueError(f"Invalid reconnect_wait configured for interface \"{name}\"")
        if (proxy_username == None) != (proxy_password == None):
            raise ValueError(f"Both proxy_username and proxy_password must be configured for interface \"{name}\"")

        socks_address = SOCKS5.address(target_host)
        socks_auth    = None
        if proxy_username != None:
            socks_auth = SOCKS5.field("proxy_username", proxy_username)+SOCKS5.field("proxy_password", proxy_password)

        tcp_configuration = dict(c)
        tcp_configuration["target_host"] = None
        super().__init__(owner, tcp_configuration)

        self.receives        = True
        self.target_ip       = target_host
        self.target_port     = target_port
        self.proxy_host      = proxy_host
        self.proxy_port      = proxy_port
        self.socks_address   = socks_address
        self.socks_auth      = socks_auth
        self.connect_timeout = connect_timeout
        self.reconnect_wait  = reconnect_wait
        self.initiator       = True

    def final_init(self):
        thread = threading.Thread(target=self.deferred_connect)
        thread.daemon = True
        thread.start()

    def deferred_connect(self):
        self.initial_connect()

        if not hasattr(self, "early_synthesis"):
            while not RNS.Transport.ready and not self.detached: time.sleep(0.25)
            time.sleep(1)
            if getattr(self, "wants_tunnel", False) and self.online: RNS.Transport.synthesize_tunnel(self)

    def connect(self, initial=False):
        # TCPClientInterface.reconnect() already waited RECONNECT_WAIT seconds
        if not initial: time.sleep(self.reconnect_wait-TCPClientInterface.RECONNECT_WAIT)

        try:
            if initial:
                RNS.log("Establishing SOCKS connection for "+str(self)+" via "+self.proxy_str()+"...", RNS.LOG_DEBUG)

            deadline     = time.monotonic()+self.connect_timeout
            address_info = socket.getaddrinfo(self.proxy_host, self.proxy_port, proto=socket.IPPROTO_TCP)[0]
            proxy_socket = socket.socket(address_info[0], socket.SOCK_STREAM)

            self.socket  = proxy_socket

            try:
                proxy_socket.settimeout(min(TCPClientInterface.INITIAL_CONNECT_TIMEOUT, self.connect_timeout))
                proxy_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                try: proxy_socket.connect(address_info[4])
                except Exception as e: raise IOError("Could not connect to SOCKS proxy at "+self.proxy_str()+": "+str(e))

                self.socks_connect(proxy_socket, deadline)
                proxy_socket.settimeout(None)

                if self.detached: raise IOError("Interface was detached while connecting")
                if platform.system() == "Linux":    self.set_timeouts_linux()
                elif platform.system() == "Darwin": self.set_timeouts_osx()

            except Exception as e:
                try: proxy_socket.close()
                except Exception: pass
                if self.socket == proxy_socket: self.socket = None
                raise e

            if hasattr(self, "early_synthesis") and not self.kiss_framing:
                self.wants_tunnel = True
                self.remote_transport = None
                self.synthesis_received = False
                RNS.Transport.synthesize_tunnel(self)

            if initial:
                RNS.log("SOCks Connection for "+str(self)+" established", RNS.LOG_DEBUG)

        except Exception as e:
            if initial:
                if not self.detached:
                    RNS.log("Initial connection for "+str(self)+" could not be established: "+str(e), RNS.LOG_ERROR)
                    RNS.log("Leaving unconnected and retrying connection in "+str(self.reconnect_wait)+" seconds.", RNS.LOG_ERROR)

                return False

            else:
                raise e

        self.online  = True
        self.writing = False
        self.never_connected = False

        return True

    def socks_connect(self, proxy_socket, deadline):
        def receive(length):
            data = b""
            while len(data) < length:
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise TimeoutError("Timed out waiting for reply from SOCKS proxy")
                proxy_socket.settimeout(remaining)
                try: chunk = proxy_socket.recv(length-len(data))
                except socket.timeout: raise TimeoutError("Timed out waiting for reply from SOCKS proxy")
                if not chunk: raise IOError("SOCKS proxy closed the connection during negotiation")
                data += chunk

            return data

        if self.socks_auth: method = SOCKS5.AUTH_USERPASS
        else:               method = SOCKS5.AUTH_NONE

        proxy_socket.sendall(bytes([SOCKS5.VERSION, 1, method]))
        version, selected = receive(2)
        if version != SOCKS5.VERSION: raise IOError("Proxy at "+self.proxy_str()+" is not a SOCKS5 proxy")
        if selected != method:
            if selected != SOCKS5.AUTH_REFUSED: raise IOError(f"SOCKS proxy selected unsupported authentication method {selected}")
            elif self.socks_auth:               raise IOError("SOCKS proxy does not accept username and password authentication")
            else:                               raise IOError("SOCKS proxy requires authentication")

        if self.socks_auth:
            proxy_socket.sendall(bytes([SOCKS5.AUTH_VERSION])+self.socks_auth)
            version, status = receive(2)
            if status != SOCKS5.SUCCEEDED: raise IOError("SOCKS proxy rejected the configured username and password")

        proxy_socket.sendall(bytes([SOCKS5.VERSION, SOCKS5.CMD_CONNECT, 0x00])+self.socks_address+struct.pack("!H", self.target_port))
        version, reply, reserved, address_type = receive(4)
        if version != SOCKS5.VERSION: raise IOError("Invalid reply from SOCKS proxy")
        if reply != SOCKS5.SUCCEEDED:
            reason = SOCKS5.REPLIES[reply] if reply in SOCKS5.REPLIES else f"error code {reply}"
            raise IOError(f"SOCKS proxy could not connect to target, {reason}")

        # read from the bound address regardless
        if   address_type == SOCKS5.ATYP_IPV4:   receive(4+2)
        elif address_type == SOCKS5.ATYP_IPV6:   receive(16+2)
        elif address_type == SOCKS5.ATYP_DOMAIN: receive(receive(1)[0]+2)
        else: raise IOError("invalid reply")

    def proxy_str(self):
        if ":" in self.proxy_host: return f"[{self.proxy_host}]:{self.proxy_port}"
        else:                      return f"{self.proxy_host}:{self.proxy_port}"

    def __str__(self):
        if ":" in self.target_ip: ip_str = f"[{self.target_ip}]"
        else:                     ip_str = f"{self.target_ip}"

        return "SOCKSInterface["+str(self.name)+"/"+ip_str+":"+str(self.target_port)+"]"

interface_class = SOCKSClientInterface
