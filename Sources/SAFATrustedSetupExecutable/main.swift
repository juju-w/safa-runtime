import SAFATrustedSetup

@main
struct SAFATrustedSetupEntryPoint {
    static func main() async {
        await TrustedSetupRuntime.main()
    }
}
