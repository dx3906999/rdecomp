use iced_x86::Code;
fn main() {
    // Test condition code extraction
    let codes = [
        Code::Je_rel8_64, Code::Je_rel32_64,
        Code::Jne_rel8_64, Code::Jne_rel32_64,
        Code::Jl_rel8_64,
    ];
    for c in &codes {
        println!("{:?} -> condition_code = {:?}", c, c.condition_code());
    }
}
