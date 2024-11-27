fn main() {
    println!("cargo:rustc-link-search=native=lib");
    //libfrida-core.a should be at the root
    println!("cargo::rustc-link-lib=static=frida-core");
}
