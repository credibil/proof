use vercre_did::Resolution;

#[tokio::main]
async fn main() {
    let endpoint = std::env::var("ION_RESOLUTION_URL").expect("ION_RESOLUTION_URL must be set");
    println!("Using endpoint: {}", endpoint);
    let did = std::env::args().nth(1).expect("Usage: universal-resolver <did>");
    println!("Resolving DID: {}", did);

    let client = reqwest::Client::new();
    let response = client
        .get(&format!("{}/{}", endpoint, did))
        .send()
        .await
        .expect("Failed to send request");

    let resolution = response.json::<Resolution>().await.expect("Failed to deserialize response");
    println!("Resolution: {:#?}", resolution);
}
