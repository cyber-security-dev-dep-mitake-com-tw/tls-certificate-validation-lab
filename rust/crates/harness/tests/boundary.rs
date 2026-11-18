#[test]
fn svc2_crate_does_not_depend_on_the_oracle() {
    let manifest = include_str!("../../svc2/Cargo.toml");
    assert!(
        !manifest.to_ascii_lowercase().contains("oracle"),
        "svc2 must not link the oracle client"
    );
}
