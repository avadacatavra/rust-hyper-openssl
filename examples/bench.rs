use std::fs::File;
use std::sync::Arc;
use std::path::Path;
use std::io::Read;
use std::time::{Duration, Instant};

extern crate hyper_openssl;
use hyper_openssl::HttpsConnector;

extern crate openssl;
use openssl::ssl::{SslRef, SSL_VERIFY_PEER, SSL_VERIFY_NONE};
use openssl::x509::X509StoreContextRef;
use hyper::Uri;

extern crate hyper;
use hyper::Client;
use hyper::client::HttpConnector;
use hyper::StatusCode;

extern crate tokio_core;
use tokio_core::reactor::Core;

extern crate rustls;
extern crate webpki_roots;

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

// FIXME this doesn't work on rust or servo sites, so i'm skipping them
// Error thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: Io(Error { repr: Custom(Custom { kind: Other, error: Ssl(ErrorStack([Error { code: 336151568, library: "SSL routines", function: "ssl3_read_bytes", reason: "sslv3 alert handshake failure", file: "ssl/record/rec_layer_s3.c", line: 1399, data: "SSL alert number 40" }])) }) })', src/libcore/result.rs:860
fn create_no_verif_client(core: &Core) -> Client<Connector> {
    let mut ssl = HttpsConnector::new(4, &core.handle()).unwrap();
    ssl.danger_disable_hostname_verification(true);
    //ssl.ssl_callback(move |s, d| {

    Client::configure()
        .connector(ssl)
        .build(&core.handle())
}

//should just time this tbh ... you're creating a separate client doing this i don't think this is what you want to do.
fn webpki_verif(uri: &Uri,
                preverify_ok: bool,
                x509_ctx: &X509StoreContextRef) -> bool {
    let uri = uri.to_owned();
    let domain = uri.path();
    let mut config = rustls::ClientConfig::new();
    //use webpki default roots
    config.root_store.add_trust_anchors(&webpki_roots::ROOTS);
    let client = rustls::ClientSession::new(&Arc::new(config), domain);

    //you can call client.get_verifier()

    true
}

fn hybrid_callback(ssl_conf: &mut SslRef, uri: &Uri) -> Result<(), openssl::error::ErrorStack> {
    let uri = uri.to_owned();
    ssl_conf.set_verify_callback(SSL_VERIFY_PEER, move |p, x| {
            webpki_verif(&uri.to_owned(),  p, x)
    });
    Ok(())
}

fn create_hybrid_client(core: &Core) -> Client<Connector> {
    let mut ssl = HttpsConnector::new(4, &core.handle()).unwrap();
    //ssl.ssl_callback(hybrid_callback);
    ssl.ssl_callback(move |s, d|{
        hybrid_callback(s, d)
    });
    Client::configure()
        .connector(ssl)
        .build(&core.handle())
}

// TODO benchmarking with SslAcceptor and SslConnector

// uses hyper openssl
fn website_bench(site: &str, exp: &Experiment) -> f64 {
    let mut core = Core::new().unwrap();
    let client = match *exp {
        Experiment::OpenSSL => create_client(&core),
        Experiment::Hybrid => create_hybrid_client(&core),
        Experiment::DANGEROUS => create_no_verif_client(&core),
    };

    let start = Instant::now();
    let res = core.run(client.get(site.parse().unwrap())).unwrap();
    // some are 302s
    //assert!(res.status().is_success() || res.status() == StatusCode::Found);
    println!("{}", res.status());
    duration_nanos(Instant::now().duration_since(start))

}

// TODO: simran create non default configuration that can interchange a different certificate verification function
// this way we can test the differences between hyper-rustls, hyper-openssl, and hyper-openssl-rustls-cert-verif

fn run(trials: i32, sites: &str, exp: &Experiment) -> Vec<f64> {
    let mut times: Vec<f64> = vec!();
    for line in sites.lines() {
        //TODO fix sites.txt
        let l: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
        let mut site = "https://".to_owned();
        site.push_str(l[0].trim());

        println!("{}", site);

        let mut site_time: Vec<f64> = vec!();
        for _ in 0..trials {
            site_time.push(
                website_bench(&site, &exp));
        }
        let avg = site_time.iter().fold(0.0, |a, &b| a + b)/(site_time.len() as f64);
        times.push(avg);
    }
    times
}

enum Experiment {
    OpenSSL,
    Hybrid,
    DANGEROUS,
}

fn main() {

    let mut file = match File::open(Path::new("./examples/sites.txt")) {
        Err(_) => panic!("sites.txt not found"),
        Ok(file) => file,
    };
    // can create a custom root-ca store (defaults to webpki)

    let mut sites = String::new();
    file.read_to_string(&mut sites).unwrap();

    println!("Average times for dangerous connection (ns)");
    for t in run(1, &sites, &Experiment::DANGEROUS) {
        println!("{}", t);
    }

    // println!("Average times for connection (ns)");
    // for t in run(10, &sites, &Experiment::OpenSSL) {
    //     println!("{}", t);
    // }

    // println!("Average times for hybrid connection (ns)");
    // for t in run(10, &sites, &Experiment::Hybrid) {
    //     println!("{}", t);
    // }


}