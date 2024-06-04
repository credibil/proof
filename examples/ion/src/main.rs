#![allow(missing_docs)]

use did_core::test_utils::{self, TestKeyRingSigner};
use vercre_did::{IonRegistrar, Resolver};

/// Calls an ION registrar that supports DID resolution to resolve a DID.
///
/// # Usage:
///
/// ```
/// ion <did>
/// ```
///
/// with ION_REGISTRATION_URL environment variable set to a suitable DID ION registration endpoint.
///
/// See `resolve.sh` for a shell script that loads the environment variable from a .env file in the
/// workspace directory and calls this binary.
///
/// # Example:
///
/// ```
/// export ION_RESOLUTION_URL=https://dev.uniresolver.io/1.0/identifiers
/// ion did:ion:EiAnKD8-jfdd0MDcZUjAbRgaThBrMxPTFOxcnfJhI7Ukaw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJzaWdfNzJiZDE2ZDYiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoiS2JfMnVOR3Nyd1VOdkh2YUNOckRGdW14VXlQTWZZd3kxNEpZZmphQUhmayIsInkiOiJhSFNDZDVEOFh0RUxvSXBpN1A5eDV1cXBpeEVxNmJDenQ0QldvUVk1UUFRIn0sInB1cnBvc2VzIjpbImF1dGhlbnRpY2F0aW9uIiwiYXNzZXJ0aW9uTWV0aG9kIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VzIjpbeyJpZCI6ImxpbmtlZGRvbWFpbnMiLCJzZXJ2aWNlRW5kcG9pbnQiOnsib3JpZ2lucyI6WyJodHRwczovL3d3dy52Y3NhdG9zaGkuY29tLyJdfSwidHlwZSI6IkxpbmtlZERvbWFpbnMifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUR4SWxJak9xQk5NTGZjdzZndWpHNEdFVDM3UjBIRWM2Z20xclNZTjlMOF9RIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBLXV3TWo3RVFheURmWTRJS3pfSE9LdmJZQ05td19Tb1lhUmhOcWhFSWhudyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQ0czQ1M5RFJpeU1JRVoxRl9sSjZnRVRMZWVHREwzZnpuQUViMVRGdFZXNEEifX0#sig_72bd16d6
/// ```
#[tokio::main]
async fn main() {
    // For resolution-only most of the configuration is unnecessary. We use a test keyring to fill
    // in the blanks, but you could also use a real key ring or a mock key ring.
    let challenge_url = "";
    let solution_url = "";
    let resolution_url =
        std::env::var("ION_RESOLUTION_URL").expect("ION_RESOLUTION_URL must be set");
    let keyring = TestKeyRingSigner {
        keyring: test_utils::keyring::Test {},
        signer: test_utils::signer::Test {},
    };
    let anchor = false;
    let network = Option::<String>::None;
    let controller = Option::<String>::None;
    let registrar = IonRegistrar::new(
        challenge_url,
        solution_url,
        &resolution_url,
        keyring,
        anchor,
        network,
        controller,
    );

    let did = std::env::args().nth(1).expect("Usage: ion <did>");
    println!("Resolving DID: {}", did);

    let resolution = registrar.resolve(&did).await.expect("Failed to resolve DID");
    println!("Resolution: {:#?}", resolution);
}
