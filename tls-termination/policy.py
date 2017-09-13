from Zorp.Core import init

from Zorp.Core import FALSE, TRUE, ZD_PROTO_TCP, DBSockAddr, SockAddrInet
from Zorp.Router import DirectedRouter
from Zorp.Dispatch import Dispatcher
from Zorp.Service import Service
from Zorp.Http import HttpProxy, HTTP_HDR_INSERT
from Zorp.Encryption import \
    EncryptionPolicy, \
    ClientOnlyEncryption, \
    ClientNoneVerifier, \
    ClientSSLOptions, \
    StaticCertificate, \
    Certificate, \
    PrivateKey, \
    SSL_METHOD_ALL, \
    SSL_CIPHERS_CUSTOM

from datetime import timedelta

from Zorp.Core import config
config.options.kzorp_enabled = False

certificate=Certificate.fromFile(
    certificate_file_path="/etc/zorp/certs/fullchain.pem",
    private_key=PrivateKey.fromFile(
        key_file_path="/etc/zorp/certs/privkey.pem",
    )
)

cipher = \
    "ECDHE-ECDSA-AES256-GCM-SHA384:" \
    "ECDHE-RSA-AES256-GCM-SHA384:" \
    "ECDHE-ECDSA-CHACHA20-POLY1305:" \
    "ECDHE-RSA-CHACHA20-POLY1305:" \
    "ECDHE-ECDSA-AES128-GCM-SHA256:" \
    "ECDHE-RSA-AES128-GCM-SHA256:" \
    "ECDHE-ECDSA-AES256-SHA384:" \
    "ECDHE-RSA-AES256-SHA384:" \
    "ECDHE-ECDSA-AES128-SHA256:" \
    "ECDHE-RSA-AES128-SHA256"

client_ssl_options=ClientSSLOptions(
    method=SSL_METHOD_ALL,
    cipher=(SSL_CIPHERS_CUSTOM, cipher),
    cipher_server_preference=TRUE,
    disable_sslv2=TRUE,
    disable_sslv3=TRUE,
    disable_tlsv1=TRUE,
    disable_tlsv1_1=TRUE,
    disable_tlsv1_2=FALSE,
    disable_compression=TRUE,
    disable_renegotiation=FALSE,
)

EncryptionPolicy(
    name="encryption_policy_tls_termination",
    encryption=ClientOnlyEncryption(
        client_certificate_generator=StaticCertificate(certificate=certificate),
        client_ssl_options=client_ssl_options,
        client_verify=ClientNoneVerifier(),
    )
)


class HttpProxySecurityHeaders(HttpProxy):
    cert_chain_digests = open("/etc/zorp/certs/cert.dgst").read().splitlines()
    ca_chain_digests = open("/etc/zorp/certs/ca.dgst").read().splitlines()

    def config(self):
        HttpProxy.config(self)

        self.response_header["Content-Security-Policy"] = (HTTP_HDR_INSERT, "default-src https:")
        self.response_header["Referrer-Policy"] = (HTTP_HDR_INSERT, "no-referrer")
        hpkp_header_values = (
            ["max-age=%d" % (timedelta(days=30).total_seconds()), ] +
            ["pin-sha256=\"" + dgst + "\"" for dgst in self.cert_chain_digests] +
            ["pin-sha256=\"" + dgst + "\"" for dgst in self.ca_chain_digests] +
            ["includeSubDomains", ]
        )
        #self.response_header["Public-Key-Pins"] = (HTTP_HDR_INSERT, ";".join(hpkp_header_values))
        hsts_header_value = "max-age=%d" % (timedelta(days=365).total_seconds())
        self.response_header["Strict-Transport-Security"] = (HTTP_HDR_INSERT, hsts_header_value)
        self.response_header["x-frame-options"] = (HTTP_HDR_INSERT, "SAMEORIGIN")
        self.response_header["X-Content-Type-Options"] = (HTTP_HDR_INSERT, "nosniff")
        self.response_header["X-XSS-Protection"] = (HTTP_HDR_INSERT, "1; mode=block")


def default():
    def getServiceList():
        import os
        service_enabled = os.getenv("ZORP_TLS_TERMINATION_SERVICE_ENABLED", "").lower().split()
        return service_enabled
    serviceList = getServiceList()

    if "https" in serviceList:
        import socket
        server_address = socket.gethostbyname("www")

        Service(
            name="service_https_tls_termination",
            proxy_class=HttpProxySecurityHeaders,
            encryption_policy="encryption_policy_tls_termination",
            router=DirectedRouter(dest_addr=SockAddrInet(server_address, 80), forge_addr=FALSE),
        )
        Dispatcher(
            bindto=DBSockAddr(SockAddrInet('0.0.0.0', 443), protocol=ZD_PROTO_TCP),
            service="service_https_tls_termination",
        )
