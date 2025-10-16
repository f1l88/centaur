use centaur_core::waf::engine::Engine;
use pingora::http::HMap;
use std::fs;
use std::path::Path;

#[test]
fn test_engine_blocks_header_contains() {
    let tmp = Path::new("test_rules.conf");
    fs::write(tmp, "SecRule REQUEST_HEADERS:User-Agent \"@contains sqlmap\" \"id:1001,phase:1,deny,status:403,msg:\'Block sqlmap user agent\'\"").unwrap();
    //SecRule REQUEST_HEADERS:User-Agent \"@contains sqlmap\" \"id:1001,phase:1,deny,status:403,msg:\'Block sqlmap user agent\'\"

    let engine = Engine::load(tmp).expect("failed to load rules");

    // Создаём headers вручную без make_headers()
    let mut headers = HMap::new();
    headers.insert("User-Agent", "curl/8.0".parse().unwrap());
    assert!(!engine.check(&headers), "curl should be blocked");

    let mut headers = HMap::new();
    headers.insert("User-Agent", "Mozilla/5.0".parse().unwrap());
    assert!(engine.check(&headers), "normal UA should be allowed");

    fs::remove_file(tmp).ok();
}
