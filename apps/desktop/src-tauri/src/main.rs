fn main() {
    if let Err(message) = compatforge_desktop::run(std::env::args_os()) {
        eprintln!("{message}");
        std::process::exit(2);
    }
}
