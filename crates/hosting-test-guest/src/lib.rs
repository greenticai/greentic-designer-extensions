wit_bindgen::generate!({ path: "../../wit/extension-hosting.wit", world: "hosting-extension" });
struct G;
impl exports::greentic::extension_hosting::provider::Guest for G {
    fn describe_provider() -> exports::greentic::extension_hosting::provider::ProviderDescriptor { todo!() }
    fn validate_settings(_: String) -> Vec<exports::greentic::extension_hosting::provider::Diagnostic> { vec![] }
    fn preflight() -> Vec<exports::greentic::extension_hosting::provider::Diagnostic> { vec![] }
    fn supports(_: String) -> bool { true }
    fn host_ref_for(_: String) -> String { String::new() }
    fn ensure_host(_: exports::greentic::extension_hosting::provider::HostSpec, _: String) -> Result<exports::greentic::extension_hosting::provider::HostOutcome, exports::greentic::extension_hosting::provider::HostError> { Err(exports::greentic::extension_hosting::provider::HostError::Rejected) }
    fn describe_host(_: String) -> Result<exports::greentic::extension_hosting::provider::HostOutcome, exports::greentic::extension_hosting::provider::HostError> { Err(exports::greentic::extension_hosting::provider::HostError::Rejected) }
    fn list_owned() -> Result<Vec<String>, exports::greentic::extension_hosting::provider::HostError> { Ok(vec![]) }
    fn destroy(_: String, _: exports::greentic::extension_hosting::provider::DestroyMode) -> Result<(), exports::greentic::extension_hosting::provider::HostError> { Ok(()) }
}
export!(G);
