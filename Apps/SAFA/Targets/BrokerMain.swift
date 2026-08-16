import SAFABroker

@main
struct SAFABrokerEntryPoint {
    static func main() async {
        await BrokerRuntime.main()
    }
}
