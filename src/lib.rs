//! Hyper SSL support via modern versions of OpenSSL.
//!
//! Hyper's built in OpenSSL support depends on version 0.7 of `openssl`. This crate provides
//! SSL support using version 0.9 of `openssl`.
//!
//! # Usage
//!
//! Hyper's `ssl` feature is enabled by default, so it must be explicitly turned off in your
//! Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! hyper = { version = "0.9", default_features = false }
//! hyper-openssl = "0.1"
//! ```
//!
//! Then on the client side:
//!
//! ```
//! extern crate hyper;
//! extern crate hyper_openssl;
//!
//! use hyper::Client;
//! use hyper::net::HttpsConnector;
//! use hyper_openssl::OpensslClient;
//! use std::io::Read;
//!
//! fn main() {
//!     let ssl = OpensslClient::new().unwrap();
//!     let connector = HttpsConnector::new(ssl);
//!     let client = Client::with_connector(connector);
//!
//!     let mut resp = client.get("https://google.com").send().unwrap();
//!     let mut body = vec![];
//!     resp.read_to_end(&mut body).unwrap();
//!     println!("{}", String::from_utf8_lossy(&body));
//! }
//! ```
//!
//! Or on the server side:
//!
//! ```no_run
//! extern crate hyper;
//! extern crate hyper_openssl;
//! extern crate openssl;
//!
//! use hyper::Server;
//! use hyper_openssl::OpensslServer;
//! use openssl::ssl::{SslMethod, SslAcceptorBuilder};
//! use openssl::pkcs12::Pkcs12;
//! use std::io::Read;
//! use std::fs::File;
//!
//! fn main() {
//!     let mut pkcs12 = vec![];
//!     File::open("identity.pfx")
//!         .unwrap()
//!         .read_to_end(&mut pkcs12)
//!         .unwrap();
//!     let pkcs12 = Pkcs12::from_der(&pkcs12)
//!         .unwrap()
//!         .parse("hunter2")
//!         .unwrap();
//!
//!     let acceptor = SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(),
//!                                                             &pkcs12.pkey,
//!                                                             &pkcs12.cert,
//!                                                             pkcs12.chain)
//!         .unwrap()
//!         .build();
//!     let ssl = OpensslServer::from(acceptor);
//!
//!     let server = Server::https("0.0.0.0:8443", ssl).unwrap();
//! }
//! ```
#![warn(missing_docs)]
#![doc(html_root_url="https://docs.rs/hyper-openssl/0.1.0")]

extern crate antidote;
extern crate hyper;
extern crate openssl;

use antidote::Mutex;
use hyper::net::{SslClient, SslServer, NetworkStream};
use openssl::error::ErrorStack;
use openssl::ssl::{self, SslMethod, SslConnector, SslConnectorBuilder, SslAcceptor};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::fmt::Debug;

/// An `SslClient` implementation using OpenSSL.
#[derive(Clone)]
pub struct OpensslClient(SslConnector);

impl OpensslClient {
    /// Creates a new `OpenSslClient` with default settings.
    pub fn new() -> Result<OpensslClient, ErrorStack> {
        let connector = try!(SslConnectorBuilder::new(SslMethod::tls())).build();
        Ok(OpensslClient(connector))
    }
}

impl From<SslConnector> for OpensslClient {
    fn from(connector: SslConnector) -> OpensslClient {
        OpensslClient(connector)
    }
}

impl<T> SslClient<T> for OpensslClient
    where T: NetworkStream + Clone + Sync + Send + Debug
{
    type Stream = SslStream<T>;

    fn wrap_client(&self, stream: T, host: &str) -> hyper::Result<SslStream<T>> {
        match self.0.connect(host, stream) {
            Ok(stream) => Ok(SslStream(Arc::new(Mutex::new(stream)))),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

/// An `SslServer` implementation using OpenSSL.
#[derive(Clone)]
pub struct OpensslServer(SslAcceptor);

impl From<SslAcceptor> for OpensslServer {
    fn from(acceptor: SslAcceptor) -> OpensslServer {
        OpensslServer(acceptor)
    }
}

impl<T> SslServer<T> for OpensslServer
    where T: NetworkStream + Clone + Sync + Send + Debug
{
    type Stream = SslStream<T>;

    fn wrap_server(&self, stream: T) -> hyper::Result<SslStream<T>> {
        match self.0.accept(stream) {
            Ok(stream) => Ok(SslStream(Arc::new(Mutex::new(stream)))),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

/// A Hyper SSL stream.
#[derive(Clone)]
pub struct SslStream<T>(pub Arc<Mutex<ssl::SslStream<T>>>);

impl<T: Read + Write> Read for SslStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().read(buf)
    }
}

impl<T: Read + Write> Write for SslStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().flush()
    }
}

impl<T: NetworkStream> NetworkStream for SslStream<T> {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.0.lock().get_mut().peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().get_ref().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.lock().get_ref().set_write_timeout(dur)
    }
}

#[cfg(test)]
mod test {
    use hyper::{Client, Server};
    use hyper::server::{Request, Response, Fresh};
    use hyper::net::HttpsConnector;
    use openssl::ssl::{SslMethod, SslAcceptorBuilder, SslConnectorBuilder};
    use openssl::pkey::PKey;
    use openssl::x509::X509;
    use std::io::Read;
    use std::mem;

    use {OpensslClient, OpensslServer};

    #[test]
    fn google() {
        let ssl = OpensslClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let mut resp = client.get("https://google.com").send().unwrap();
        assert!(resp.status.is_success());
        let mut body = vec![];
        resp.read_to_end(&mut body).unwrap();
    }

    #[test]
    fn server() {
        let cert = include_bytes!("../test/cert.pem");
        let key = include_bytes!("../test/key.pem");

        let cert = X509::from_pem(cert).unwrap();
        let key = PKey::private_key_from_pem(key).unwrap();

        let acceptor = SslAcceptorBuilder::mozilla_intermediate(SslMethod::tls(),
                                                                &key,
                                                                &cert,
                                                                None::<X509>)
            .unwrap()
            .build();
        let ssl = OpensslServer::from(acceptor);
        let server = Server::https("127.0.0.1:0", ssl).unwrap();

        let listening = server.handle(|_: Request, resp: Response<Fresh>| {
            resp.send(b"hello").unwrap()
        }).unwrap();
        let port = listening.socket.port();
        mem::forget(listening);

        let mut connector = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
        connector.builder_mut().cert_store_mut().add_cert(cert).unwrap();
        let ssl = OpensslClient::from(connector.build());
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);

        let mut resp = client.get(&format!("https://localhost:{}", port))
            .send()
            .unwrap();
        let mut body = vec![];
        resp.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"hello");
    }
}
