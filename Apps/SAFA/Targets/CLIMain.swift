import SAFACLI

@main
struct SAFACLIEntryPoint {
    static func main() async {
        await SAFACommand.runMain()
    }
}
