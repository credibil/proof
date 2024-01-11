use vercre_did::Resolution;

/// Calls an ION resolver to resolve a DID.
///
/// # Usage:
///
/// ```
/// universal-resolver <did>
/// ```
///
/// with ION_RESOLUTION_URL environment variable set to a suitable DID ION resolution endpoint.
///
/// See `resolve.sh` for a shell script that loads the environment variable from a .env file in the
/// workspace directory and calls this binary.
///
/// # Example:
///
/// ```
/// export ION_RESOLUTION_URL=https://dev.uniresolver.io/1.0/identifiers
/// universal-resolver did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0#sig_72bd16d6
/// ```
#[tokio::main]
async fn main() {
    let endpoint = std::env::var("ION_RESOLUTION_URL").expect("ION_RESOLUTION_URL must be set");
    println!("Using endpoint: {}", endpoint);
    let did = std::env::args().nth(1).expect("Usage: universal-resolver <did>");
    println!("Resolving DID: {}", did);

    let client = reqwest::Client::new();
    let response =
        client.get(&format!("{}/{}", endpoint, did)).send().await.expect("Failed to send request");

    let resolution = response.json::<Resolution>().await.expect("Failed to deserialize response");
    println!("Resolution: {:#?}", resolution);
}
