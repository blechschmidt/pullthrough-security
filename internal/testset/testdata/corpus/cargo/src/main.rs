// Minimal real cargo build for the pull-through proxy test set.
fn main() {
    cfg_if::cfg_if! {
        if #[cfg(unix)] { println!("cfg-if ok (unix)"); }
        else { println!("cfg-if ok"); }
    }
}
