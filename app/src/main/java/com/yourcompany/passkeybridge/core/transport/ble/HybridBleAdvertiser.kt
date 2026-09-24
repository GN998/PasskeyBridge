package com.yourcompany.passkeybridge.core.transport.ble

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.os.ParcelUuid
import android.util.Log
import java.util.UUID

class HybridBleAdvertiser(private val advertiser: BluetoothLeAdvertiser?) {

    private val FIDO_SERVICE_UUID = UUID.fromString("0000fff0-0000-1000-8000-00805f9b34fb")

    fun startAdvertising(eid: ByteArray) {
        if (advertiser == null) {
            Log.e("HybridBleAdvertiser", "BLE Advertiser not available")
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(false)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(FIDO_SERVICE_UUID))
            .addServiceData(ParcelUuid(FIDO_SERVICE_UUID), eid)
            .build()

        advertiser.startAdvertising(settings, data, object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.d("HybridBleAdvertiser", "EID BLE Advertising started successfully")
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e("HybridBleAdvertiser", "EID BLE Advertising failed: $errorCode")
            }
        })
    }
}