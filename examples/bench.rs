use std::fs::File;
use std::path::Path;
use std::io::Read;
use std::time::{Duration, Instant};

extern crate hyper_openssl;
use hyper_openssl::HttpsConnector;

extern crate openssl;
use openssl::ssl::{SslMethod, SslConnector, SslConnectorBuilder, SslSession, SslRef, SSL_VERIFY_PEER};
use openssl::x509::X509StoreContextRef;
use hyper::Uri;

extern crate hyper;
use hyper::Client;
use hyper::client::HttpConnector;
use hyper::StatusCode;

extern crate tokio_core;
use tokio_core::reactor::Core;

extern crate rustls;

// struct hybrid_client {

// }

// impl SslClient for hybrid_client() {

// }

type Connector = HttpsConnector<HttpConnector>;

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + (d.subsec_nanos() as f64) / 1e9
}

// uses default configuration
fn create_client(core: &Core) -> Client<Connector> {
	Client::configure()
         .connector(HttpsConnector::new(4, &core.handle()).unwrap())
         .build(&core.handle())
}

// no verification for base case
fn create_no_verif_client(core: &Core) -> Client<Connector> {
    let ssl = HttpsConnector::new(4, &core.handle()).unwrap();
    ssl.danger_disable_hostname_verification(true);
    Client::configure()
        .connector(ssl)
        .build(&core.handle())
}

fn webpki_verif(domain: &str,
                roots: &RootCertStore,
                preverify_ok: bool,
                x509_ctx: &X509StoreContextRef) -> bool {
    let mut config = rustls::ClientConfig::new();
    //use webpki default roots
    config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
    true
}

fn hybrid_callback(ssl_conf: SslRef, domain: &Uri) {
    ssl_conf.set_verify_callback(SSL_VERIFY_PEER, move |p, x| {
            webpki_verif(&domain.path(), &roots, p, x)
    })

}

fn create_hybrid_client(core: &Core) {//-> Client<Connector> {
    let ssl = HttpsConnector::new(4, &core.handle()).unwrap();
    //ssl.ssl_callback(hybrid_callback);

}

// TODO benchmarking with SslAcceptor and SslConnector

// uses hyper openssl
pub fn website_bench(site: &str) -> f64 {
    let mut core = Core::new().unwrap();
    let client = create_client(&core);


    let start = Instant::now();
    let res = core.run(client.get(site.parse().unwrap())).unwrap();
    // some are 302s
    assert!(res.status().is_success() || res.status() == StatusCode::Found);
    duration_nanos(Instant::now().duration_since(start))

}

// TODO: simran create non default configuration that can interchange a different certificate verification function
// this way we can test the differences between hyper-rustls, hyper-openssl, and hyper-openssl-rustls-cert-verif

fn main() {

    let mut file = match File::open(Path::new("./examples/sites.txt")) {
        Err(_) => panic!("sites.txt not found"),
        Ok(file) => file,
    };
    // can create a custom root-ca store (defaults to webpki)

    let mut sites = String::new();
    file.read_to_string(&mut sites).unwrap();

    

    let mut times: Vec<f64> = vec!();
    for line in sites.lines() {
        //TODO fix sites.txt
        let l: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
        let mut site = "https://".to_owned();
        site.push_str(l[0].trim());

        let mut site_time: Vec<f64> = vec!();
        for _ in 0..10 {
            site_time.push(
                website_bench(&site));
        }
        let avg = site_time.iter().fold(0.0, |a, &b| a + b)/(site_time.len() as f64);
        times.push(avg);
    }

    println!("Average times for connection (ns)");
    for t in times {
        println!("{}", t)
    }
}