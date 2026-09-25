package com.yourcompany.passkeybridge.core.transport.ble

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

class HybridBleAdvertiser(private val advertiser: BluetoothLeAdvertiser?) {

    private val FIDO_SERVICE_UUID = UUID.fromString("0000fff9-0000-1000-8000-00805f9b34fb")
    private var activeCallback: AdvertiseCallback? = null

    fun startAdvertising(eid: ByteArray) {
        if (advertiser == null) {
            Log.e("HybridBleAdvertiser", "BLE Advertiser not available")
            return
        }

        // Stop any active advertising before starting a new session
        stopAdvertising()

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(false)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(FIDO_SERVICE_UUID))
            .addServiceData(ParcelUuid(FIDO_SERVICE_UUID), eid)
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .build()

        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.d("HybridBleAdvertiser", "EID BLE Advertising started successfully")
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e("HybridBleAdvertiser", "EID BLE Advertising failed with error code: $errorCode")
            }
        }
        activeCallback = callback

        try {
            advertiser.startAdvertising(settings, data, callback)
        } catch (e: SecurityException) {
            Log.e("HybridBleAdvertiser", "SecurityException: Missing required BLE/Location permissions", e)
        } catch (e: Exception) {
            Log.e("HybridBleAdvertiser", "Unexpected error starting BLE advertising", e)
        }
    }

    fun stopAdvertising() {
        val callback = activeCallback ?: return
        try {
            advertiser?.stopAdvertising(callback)
            Log.d("HybridBleAdvertiser", "BLE Advertising stopped")
        } catch (e: Exception) {
            Log.w("HybridBleAdvertiser", "Failed to stop BLE advertising", e)
        } finally {
            activeCallback = null
        }
    }
}
