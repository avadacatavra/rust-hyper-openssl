use std::fs::File;
use std::path::Path;
use std::io::Read;
use std::time::{Duration, Instant};

extern crate hyper_openssl;
use hyper_openssl::HttpsConnector;

extern crate hyper;
use hyper::Client;
use hyper::client::HttpConnector;
use hyper::StatusCode;

extern crate tokio_core;
use tokio_core::reactor::Core;

fn duration_nanos(d: Duration) -> f64 {
    (d.as_secs() as f64) + (d.subsec_nanos() as f64) / 1e9
}

// uses default configuration
fn create_client(core: &Core) -> Client<HttpsConnector<HttpConnector>> {
	Client::configure()
         .connector(HttpsConnector::new(4, &core.handle()).unwrap())
         .build(&core.handle())
}

// TODO benchmarking with SslAcceptor and SslConnector

// uses hyper openssl
pub fn website_bench() {
	let mut file = match File::open(Path::new("./examples/sites.txt")) {
        Err(_) => return,   //fail silently
        Ok(file) => file,
    };

    
    let mut sites = String::new();
    file.read_to_string(&mut sites).unwrap();

    let start = Instant::now();
    let mut core = Core::new().unwrap();
    let client = create_client(&core);
    println!("Client creation time: {}", duration_nanos(Instant::now().duration_since(start)));

    let mut times = vec!();
    for line in sites.lines(){
        let l: Vec<String> = line.split(',').map(|s| s.to_string()).collect();
        let mut site = "https://".to_owned();
        site.push_str(l[0].trim());
        //let expected = l[1].trim();

        let start = Instant::now();
        let res = core.run(client.get(site.parse().unwrap())).unwrap();
        // some are 302s
        assert!(res.status().is_success() || res.status() == StatusCode::Found);
        times.push(duration_nanos(Instant::now().duration_since(start)));
    }
    println!("{:?}", times);

}

// TODO: simran create non default configuration that can interchange a different certificate verification function

pub fn main() {
	website_bench();
}